#!/usr/bin/env bash
# test_grc_common_venv.sh: shell-level coverage for grc_ensure_venv() in
# bin/_grc-common.sh (ELI-632: a failed requirements install must not leave a
# venv that every later launcher run skips).
#
# Why this lives outside the pytest suite: the launchers are bash that build a
# venv and run pip on first use. There is no Python seam for that, and a real
# venv plus a real pip install needs the network. So python3 and the venv
# interpreter are fakes on PATH: the fake python3 builds a fake venv, and the
# fake venv interpreter fakes `-m pip install`, failing on demand.
#
# The launcher runs against a temporary copy of bin/ and requirements.txt, so
# the repo's real .venv is never read or written.
#
# Run:
#   bash tests/shell/test_grc_common_venv.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$HERE/../.."

pass=0
fail=0

check() {
    local desc="$1" want_status="$2" got_status="$3" got_output="$4" want_grep="${5:-}"
    if [ "$got_status" -ne "$want_status" ]; then
        echo "FAIL: $desc (exit $got_status, wanted $want_status)"
        echo "  output: $got_output"
        fail=$((fail + 1))
        return
    fi
    if [ -n "$want_grep" ] && ! printf '%s' "$got_output" | grep -qF "$want_grep"; then
        echo "FAIL: $desc (output missing '$want_grep')"
        echo "  output: $got_output"
        fail=$((fail + 1))
        return
    fi
    echo "PASS: $desc"
    pass=$((pass + 1))
}

pass_case() { echo "PASS: $1"; pass=$((pass + 1)); }
fail_case() { echo "FAIL: $1"; [ -n "${2:-}" ] && echo "  $2"; fail=$((fail + 1)); }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- fixture: a fake python3 that builds a fake venv ----------------------- #
# As python3 (`-m venv DIR`) it creates DIR/bin/python as a symlink back to
# itself. With FAKE_VENV_BROKEN=1 it fails the way a venv does without
# ensurepip: the interpreter is there, pip is not, exit 1.
# As the venv interpreter it answers:
#   -c ...                  the version in FAKE_PY_VERSION (default 3.10)
#   -m pip --version        fails while DIR/bin/pip-missing exists
#   -m pip install ... -r   logs one line to $PIP_LOG per requirements attempt,
#                           exits 1 when FAKE_PIP_FAIL=1 or pip is missing
#   -m pip install (other)  succeeds and is not logged
mkdir -p "$work/fakebin"
cat > "$work/fakebin/python3" <<'FAKE'
#!/usr/bin/env bash
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "venv" ]; then
    mkdir -p "$3/bin"
    ln -sf "$0" "$3/bin/python"
    if [ "${FAKE_VENV_BROKEN:-0}" = "1" ]; then
        : > "$3/bin/pip-missing"
        echo "fake venv: ensurepip is not available" >&2
        exit 1
    fi
    rm -f "$3/bin/pip-missing"
    exit 0
fi
if [ "${1:-}" = "-c" ]; then
    echo "${FAKE_PY_VERSION:-3.10}"
    exit 0
fi
pip_missing=0
[ -e "$(dirname "$0")/pip-missing" ] && pip_missing=1
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ] && [ "${3:-}" = "--version" ]; then
    if [ "$pip_missing" -eq 0 ]; then exit 0; fi
    echo "No module named pip" >&2
    exit 1
fi
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ] && [ "${3:-}" = "install" ]; then
    if [ "$pip_missing" -eq 1 ]; then
        echo "No module named pip" >&2
        exit 1
    fi
    case " $* " in
        *" -r "*)
            echo "attempt" >> "$PIP_LOG"
            if [ "${FAKE_PIP_FAIL:-0}" = "1" ]; then
                echo "fake pip: simulated failure" >&2
                exit 1
            fi
            ;;
    esac
    exit 0
fi
echo "fake python: unexpected args: $*" >&2
exit 2
FAKE
chmod +x "$work/fakebin/python3"
export PIP_LOG="$work/pip.log"

# A fresh GRC_HOME: a copy of the launcher helper and requirements.txt.
new_home() {
    local home
    home="$(mktemp -d "$work/home.XXXXXX")"
    mkdir -p "$home/bin"
    cp "$REPO/bin/_grc-common.sh" "$home/bin/"
    cp "$REPO/requirements.txt" "$home/"
    echo "$home"
}

# Run grc_ensure_venv for GRC_HOME=$1 with FAKE_PIP_FAIL=$2, FAKE_VENV_BROKEN=${3:-0}
# and FAKE_PY_VERSION=${4:-3.10}. The fake python3 is first on PATH. Output goes
# to stdout; the exit status is the function's.
run_ensure() {
    local home="$1" fail="$2" broken="${3:-0}" pyver="${4:-3.10}"
    env GRC_HOME="$home" FAKE_PIP_FAIL="$fail" FAKE_VENV_BROKEN="$broken" \
        FAKE_PY_VERSION="$pyver" PATH="$work/fakebin:$PATH" \
        bash -c 'source "$1/bin/_grc-common.sh"; grc_ensure_venv' _ "$home" 2>&1
}

# Number of requirements install attempts logged so far.
attempts() {
    if [ -f "$PIP_LOG" ]; then wc -l < "$PIP_LOG" | tr -d ' '; else echo 0; fi
}

stamp_of() { echo "$1/.venv/.grc-deps-stamp"; }

# --- 1. a failed install is retried, not skipped (AC1, AC2) ---------------- #
home="$(new_home)"
rm -f "$PIP_LOG"
out="$(run_ensure "$home" 1)"
status=$?
check "failed requirements install dies" 1 "$status" "$out" "pip install of requirements failed"
if [ ! -e "$(stamp_of "$home")" ]; then
    pass_case "failed install leaves no stamp"
else
    fail_case "failed install leaves no stamp" "stamp exists after a failed install"
fi

out="$(run_ensure "$home" 0)"
status=$?
check "run after failed install succeeds" 0 "$status" "$out"
if [ "$(attempts)" -eq 2 ]; then
    pass_case "run after failed install reinstalls requirements"
else
    fail_case "run after failed install reinstalls requirements" \
        "attempts=$(attempts), wanted 2 (the venv was skipped)"
fi
if [ -f "$(stamp_of "$home")" ]; then
    pass_case "successful install writes the stamp"
else
    fail_case "successful install writes the stamp" "no stamp after a successful install"
fi

# --- 2. an old stamp is removed before a reinstall that fails (AC2) -------- #
home="$(new_home)"
run_ensure "$home" 0 >/dev/null
rm -f "$PIP_LOG"
: > "$(stamp_of "$home")"
touch -d '2000-01-01' "$(stamp_of "$home")"
touch -d '+1 day' "$home/requirements.txt"
out="$(run_ensure "$home" 1)"
status=$?
check "reinstall forced by newer requirements dies when pip fails" 1 "$status" "$out" \
    "pip install of requirements failed"
if [ ! -e "$(stamp_of "$home")" ]; then
    pass_case "failed reinstall removes the old stamp"
else
    fail_case "failed reinstall removes the old stamp" "old stamp survived a failed reinstall"
fi
out="$(run_ensure "$home" 0)"
status=$?
check "run after failed reinstall succeeds" 0 "$status" "$out"
if [ "$(attempts)" -eq 2 ]; then
    pass_case "run after failed reinstall reinstalls requirements"
else
    fail_case "run after failed reinstall reinstalls requirements" \
        "attempts=$(attempts), wanted 2"
fi

# --- 3. a fresh stamp skips the install (AC3, guard against over-reinstall) #
home="$(new_home)"
run_ensure "$home" 0 >/dev/null
rm -f "$PIP_LOG"
out="$(run_ensure "$home" 1)"
status=$?
check "fresh stamp skips the install" 0 "$status" "$out"
if [ "$(attempts)" -eq 0 ]; then
    pass_case "fresh stamp logs no install attempt"
else
    fail_case "fresh stamp logs no install attempt" "attempts=$(attempts), wanted 0"
fi

# --- 4. a stamp older than requirements.txt forces a reinstall (AC3) ------- #
home="$(new_home)"
run_ensure "$home" 0 >/dev/null
rm -f "$PIP_LOG"
: > "$(stamp_of "$home")"
touch -d '2000-01-01' "$(stamp_of "$home")"
out="$(run_ensure "$home" 0)"
status=$?
check "stale stamp run succeeds" 0 "$status" "$out"
if [ "$(attempts)" -eq 1 ]; then
    pass_case "stamp older than requirements.txt triggers a reinstall"
else
    fail_case "stamp older than requirements.txt triggers a reinstall" \
        "attempts=$(attempts), wanted 1"
fi

# --- 5. a venv left without pip by a failed creation is repaired ---------- #
# Regression for review finding 1: `python3 -m venv` can fail after creating
# bin/python (no ensurepip). The next run sees an interpreter, so it must
# still check pip and rebuild the venv in place before installing.
home="$(new_home)"
rm -f "$PIP_LOG"
out="$(run_ensure "$home" 0 1)"
status=$?
check "venv creation without pip dies" 1 "$status" "$out" "could not create the venv"
out="$(run_ensure "$home" 0 0)"
status=$?
check "run after a half-built venv succeeds" 0 "$status" "$out"
if [ "$(attempts)" -eq 1 ]; then
    pass_case "half-built venv gets pip repaired and deps installed"
else
    fail_case "half-built venv gets pip repaired and deps installed" \
        "attempts=$(attempts), wanted 1"
fi

# --- 6. a stamp from another Python version does not count ----------------- #
# Regression for review finding 2: a venv whose interpreter changed (OS
# upgrade behind the same python3 link) has site-packages under another
# lib/pythonX.Y, so the old stamp must not count as fresh.
home="$(new_home)"
run_ensure "$home" 0 0 3.10 >/dev/null
rm -f "$PIP_LOG"
out="$(run_ensure "$home" 0 0 3.12)"
status=$?
check "run after a Python version change succeeds" 0 "$status" "$out"
if [ "$(attempts)" -eq 1 ]; then
    pass_case "Python version change triggers a reinstall"
else
    fail_case "Python version change triggers a reinstall" \
        "attempts=$(attempts), wanted 1"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

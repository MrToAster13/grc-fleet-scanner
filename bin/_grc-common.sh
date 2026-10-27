# Shared helpers for the grc-* launchers. SOURCED, never executed directly.
#
# The launchers are thin: they locate the repo (via ~/.config/grc/env, written
# by install.sh), make sure a virtualenv with the deps exists (building it on
# first use), then hand off to `python -m grc_auditor`. Keeping that logic here
# means every command behaves identically and there's one place to fix it.

set -euo pipefail

GRC_ENV="${GRC_ENV:-${XDG_CONFIG_HOME:-$HOME/.config}/grc/env}"

grc_die() { echo "grc: $*" >&2; exit 1; }

grc_load_env() {
    [ -f "$GRC_ENV" ] || grc_die \
        "not set up yet ($GRC_ENV missing). Run ./install.sh from the grc-fleet-scanner repo."
    # shellcheck disable=SC1090
    . "$GRC_ENV"
    [ -n "${GRC_HOME:-}" ] || grc_die "$GRC_ENV does not define GRC_HOME -- re-run ./install.sh."
    [ -d "$GRC_HOME" ]     || grc_die "GRC_HOME=$GRC_HOME no longer exists -- re-run ./install.sh."
}

grc_base_python() {
    if command -v python3 >/dev/null 2>&1; then echo python3
    elif command -v python >/dev/null 2>&1; then echo python
    else return 1; fi
}

# Echo the interpreter inside a venv (POSIX bin/), or return non-zero if it
# has none yet. The launcher layer (install.sh, bin/*, grc-target-setup) is
# bash and requires a Linux run host (docs/design.md SS2), so there is no
# Windows `Scripts/python.exe` layout to account for here.
grc_venv_python() {
    if [ -x "$1/bin/python" ]; then echo "$1/bin/python"
    else return 1; fi
}

# The venv interpreter's major.minor version, e.g. 3.12.
grc_py_version() {
    "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])'
}

# True when the deps stamp exists, is at least as new as requirements.txt, and
# records the Python version the venv's interpreter reports now. The stamp is
# written only after pip install succeeds, so a failed install, a
# requirements.txt edited since the last good install, or a Python version
# change (site-packages moves to another lib/pythonX.Y) all read as stale.
grc_deps_fresh() {
    [ -f "$1" ] && ! [ "$2" -nt "$1" ] && [ "$(cat "$1")" = "$3" ]
}

# Ensure $GRC_HOME/.venv exists with the deps installed, then export GRC_PY (the
# venv interpreter) and PYTHONPATH (so grc_auditor / smoketest import from the
# repo). This is the "self-bootstrap on first run" step -- no manual venv needed.
# The venv and the deps are checked separately: a venv whose pip install failed
# has an interpreter but no stamp, so the next run reinstalls instead of skipping.
grc_ensure_venv() {
    local venv="$GRC_HOME/.venv"
    local req="$GRC_HOME/requirements.txt"
    local stamp="$venv/.grc-deps-stamp"
    local base pyver
    if ! GRC_PY="$(grc_venv_python "$venv")"; then
        base="$(grc_base_python)" || grc_die "no python3 on PATH -- install Python 3.10+."
        echo "grc: first run -- creating virtualenv in $venv ..." >&2
        "$base" -m venv "$venv" \
            || grc_die "could not create the venv (try: sudo apt install -y python3-venv)."
        GRC_PY="$(grc_venv_python "$venv")" \
            || grc_die "venv created but no python found inside $venv."
    fi
    pyver="$(grc_py_version "$GRC_PY")" \
        || grc_die "could not read the Python version of $GRC_PY."
    if ! grc_deps_fresh "$stamp" "$req" "$pyver"; then
        echo "grc: installing Python dependencies ..." >&2
        # Drop the old stamp first, so a failed install leaves none behind and
        # the next run retries rather than trusting an earlier good install.
        rm -f "$stamp"
        if ! "$GRC_PY" -m pip --version >/dev/null 2>&1; then
            # A venv left half-built (python3-venv missing when it was first
            # created) has an interpreter but no pip. Running venv again on the
            # existing directory restores pip in place, so nothing is deleted.
            base="$(grc_base_python)" || grc_die "no python3 on PATH -- install Python 3.10+."
            "$base" -m venv "$venv" \
                || grc_die "could not repair the venv (try: sudo apt install -y python3-venv)."
        fi
        "$GRC_PY" -m pip install --quiet --upgrade pip || true
        "$GRC_PY" -m pip install --quiet -r "$req" \
            || grc_die "pip install of requirements failed."
        printf '%s\n' "$pyver" > "$stamp"
    fi
    export GRC_PY PYTHONPATH="$GRC_HOME${PYTHONPATH:+:$PYTHONPATH}"
}

grc_setup() { grc_load_env; grc_ensure_venv; }

# Run the CLI from the caller's CWD (so a bare ./config.yaml resolves for the
# operator); the repo is already importable via PYTHONPATH (grc_ensure_venv).
# exec so the tool's exit code is the launcher's.
grc_run_tool() {
    exec "$GRC_PY" -m grc_auditor "$@"
}

#!/usr/bin/env bash
# test_target_setup_integrity.sh: shell-level coverage for verify_sha512sum()
# in grc-target-setup (ELI-137, the SCAP-content-integrity fix).
#
# Why this lives outside the pytest suite: grc-target-setup is bash that
# scp's alone onto a target host and runs installer steps (apt, sudoers,
# real root paths) the Python test suite has no seam to exercise, and no
# target host to run against. verify_sha512sum() is the one piece of new
# logic the fix adds, and it is a pure function: given a file and a
# sha512sum-format checksum file, it either confirms the digest or dies.
# That's testable in isolation without a target, a network, or root.
#
# Sourcing grc-target-setup with GRC_TARGET_SETUP_TEST=1 set stops the file
# right after verify_sha512sum() is defined (see the guard in the script)
# and before any of the installer body runs, so sourcing it here never
# touches this machine.
#
# Run:
#   bash tests/shell/test_target_setup_integrity.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../../grc-target-setup"

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

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- fixture: a file and its real, matching sha512sum-format checksum ----- #
printf 'ssg content stand-in\n' > "$work/good.bin"
( cd "$work" && sha512sum good.bin > good.bin.sha512 )

# 1. matching digest: succeeds and reports the digest it verified.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    verify_sha512sum "$2" "$3"
' _ "$SCRIPT" "$work/good.bin" "$work/good.bin.sha512" 2>&1)"
status=$?
check "matching digest verifies" 0 "$status" "$out" "checksum verified:"

# 2. tampered content after the checksum was recorded: fails closed.
printf 'ssg content stand-in, tampered\n' > "$work/tampered.bin"
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    verify_sha512sum "$2" "$3"
' _ "$SCRIPT" "$work/tampered.bin" "$work/good.bin.sha512" 2>&1)"
status=$?
check "mismatched digest dies" 1 "$status" "$out" "checksum mismatch"

# 3. checksum download came back empty (e.g. network blip, 404 page saved
#    as the sumfile): fails closed rather than treating "no digest" as pass.
: > "$work/empty.sha512"
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    verify_sha512sum "$2" "$3"
' _ "$SCRIPT" "$work/good.bin" "$work/empty.sha512" 2>&1)"
status=$?
check "empty checksum file dies" 1 "$status" "$out" "missing or empty"

# 4. checksum file never downloaded at all: fails closed, same as case 3.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    verify_sha512sum "$2" "$3"
' _ "$SCRIPT" "$work/good.bin" "$work/does-not-exist.sha512" 2>&1)"
status=$?
check "missing checksum file dies" 1 "$status" "$out" "missing or empty"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

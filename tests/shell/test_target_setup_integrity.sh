#!/usr/bin/env bash
# test_target_setup_integrity.sh: shell-level coverage for verify_sha512sum()
# and validate_pubkey() in grc-target-setup (ELI-137 SCAP-content-integrity
# fix; validate_pubkey added under ELI-144).
#
# Why this lives outside the pytest suite: grc-target-setup is bash that
# scp's alone onto a target host and runs installer steps (apt, sudoers,
# real root paths) the Python test suite has no seam to exercise, and no
# target host to run against. verify_sha512sum() and validate_pubkey() are
# both pure functions -- given their inputs, they either succeed or die --
# so they're testable in isolation without a target, a network, or root.
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

# --- validate_pubkey() ------------------------------------------------- #

# 5. a real-shaped ed25519 key: succeeds silently (no output on success).
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_pubkey "$2"
' _ "$SCRIPT" "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJcTiTVdbLQxAaeWv5A6zBhV6h/nMGa+7T39V6EE0Bta scan@runhost" 2>&1)"
status=$?
check "valid ed25519 pubkey passes" 0 "$status" "$out"

# 6. an unrecognized key type: dies with a clear message.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_pubkey "$2"
' _ "$SCRIPT" "ssh-made-up-type AAAAC3NzaC1lZDI1NTE5AAAA" 2>&1)"
status=$?
check "unrecognized key type dies" 1 "$status" "$out" "unrecognized key type"

# 7. non-base64 data field: dies with a clear message.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_pubkey "$2"
' _ "$SCRIPT" "ssh-ed25519 not!valid!base64!!" 2>&1)"
status=$?
check "invalid base64 data dies" 1 "$status" "$out" "not valid base64"

# 8. a plain filesystem path mistakenly passed as the key itself (the
#    concern the ticket names directly): dies with a clear message rather
#    than silently landing in authorized_keys.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_pubkey "$2"
' _ "$SCRIPT" "/home/user/.ssh/id_ed25519.pub" 2>&1)"
status=$?
check "plain path string dies" 1 "$status" "$out" "does not look like an SSH public key"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

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

# 9. CRLF-terminated key (Windows-edited key file or copy/paste): the
#    trailing \r must be stripped before the base64 check runs on any awk,
#    not just gawk, or the verdict depends on which awk is stock (mawk on
#    Ubuntu leaves \r on the last field and fails base64 -d).
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_pubkey "$2"
' _ "$SCRIPT" $'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJcTiTVdbLQxAaeWv5A6zBhV6h/nMGa+7T39V6EE0Bta scan@runhost\r' 2>&1)"
status=$?
check "CRLF-terminated valid key passes" 0 "$status" "$out"

# 10. a two-line value (e.g. a key file with a stray blank line, or two
#     keys concatenated): must be rejected outright, not silently
#     truncated to whichever fields awk happens to read from line one.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_pubkey "$2"
' _ "$SCRIPT" $'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJcTiTVdbLQxAaeWv5A6zBhV6h/nMGa+7T39V6EE0Bta scan@runhost\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAother second@runhost' 2>&1)"
status=$?
check "two-line value dies" 1 "$status" "$out" "more than one line"

# 11. normalize_pubkey() strips the CR from the bytes that actually get
#     written to authorized_keys (not just from validate_pubkey()'s local
#     copy): a CRLF key with no comment must come out CR-free.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    normalize_pubkey "$2"
' _ "$SCRIPT" $'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJcTiTVdbLQxAaeWv5A6zBhV6h/nMGa+7T39V6EE0Bta\r')"
status=$?
if [ "$status" -eq 0 ] && ! printf '%s' "$out" | grep -qF $'\r'; then
    echo "PASS: normalize_pubkey strips CR from the bytes written to authorized_keys"
    pass=$((pass + 1))
else
    echo "FAIL: normalize_pubkey left a CR in the bytes written to authorized_keys"
    echo "  output: $out"
    fail=$((fail + 1))
fi

# --- ELI-718: least-privilege sudoers rule and restricted key line ---------- #
# tests/test_target_setup_sudoers.py checks that the rule covers every command
# the scanner runs under sudo and nothing else. These cases check the syntax
# with visudo and the key line options.
KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJcTiTVdbLQxAaeWv5A6zBhV6h/nMGa+7T39V6EE0Bta scan@runhost'
DS=/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# 12. the generated drop-in passes visudo -c.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    scan_sudoers grc-scan /usr/bin/true /usr/bin/oscap /usr/bin/rm "$2"
' _ "$SCRIPT" "$DS" 2>/dev/null)"
status=$?
check "scan_sudoers writes a rule" 0 "$status" "$out" "NOPASSWD:"
printf '%s\n' "$out" > "$work/grc-scan.sudoers"
# GRC_VISUDO overrides the lookup (test_harness_skips.sh uses it). A missing
# visudo is a SKIP on a dev host, since Git for Windows ships none and the
# pre-commit hook runs this file. When CI is set it is a FAIL, so CI on ubuntu
# keeps enforcing the check.
VISUDO="${GRC_VISUDO:-$(command -v visudo || echo /usr/sbin/visudo)}"
if [ -x "$VISUDO" ]; then
    vout="$("$VISUDO" -cf "$work/grc-scan.sudoers" 2>&1)"
    check "visudo -c accepts the generated rule" 0 "$?" "$vout" "parsed OK"
elif [ -n "${CI:-}" ]; then
    echo "FAIL: visudo not found, cannot check the generated rule"
    fail=$((fail + 1))
else
    echo "SKIP: visudo not found, the generated rule was not checked (CI runs this check)"
fi

# 13. the drop-in grants no blanket command.
if printf '%s' "$out" | grep -qE 'NOPASSWD: *ALL|\(ALL\)'; then
    echo "FAIL: scan_sudoers still grants ALL"
    echo "  output: $out"
    fail=$((fail + 1))
else
    echo "PASS: scan_sudoers grants no ALL command or runas"
    pass=$((pass + 1))
fi

# 14. the authorized_keys line carries from= and restrict.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    authorized_key_line "$2" "$3"
' _ "$SCRIPT" "10.0.10.5" "$KEY" 2>/dev/null)"
status=$?
check "authorized_key_line prefixes from= and restrict" 0 "$status" "$out" \
    "from=\"10.0.10.5\",restrict $KEY"

# 15. a --from value that could break out of the quoted option dies.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_from "$2"
' _ "$SCRIPT" '10.0.10.5",command="sh' 2>&1)"
status=$?
check "validate_from rejects a quote" 1 "$status" "$out" "cannot hold"

# 16. an empty --from dies.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_from ""
' _ "$SCRIPT" 2>&1)"
status=$?
check "validate_from rejects an empty value" 1 "$status" "$out" "needs the run host"

# 17. a host list and a CIDR pass.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    validate_from "10.0.10.5,10.0.20.0/24,runhost.lab"
' _ "$SCRIPT" 2>&1)"
status=$?
check "validate_from accepts hosts and a CIDR" 0 "$status" "$out"

# 18. a key given without --from dies before anything is written.
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    require_from_for_key "$2" "" ""
' _ "$SCRIPT" "$KEY" 2>&1)"
status=$?
check "a --pubkey without --from dies" 1 "$status" "$out" "needs --from"

# 19. upsert_key_line replaces an older line for the same key (an unrestricted
#     line from an earlier setup) and keeps other keys.
printf '%s\n%s\n' "$KEY" 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherKeyOtherKey other@host' \
    > "$work/authorized_keys"
out="$(GRC_TARGET_SETUP_TEST=1 bash -c '
    source "$1"
    upsert_key_line "$2" "$(authorized_key_line 10.0.10.5 "$2")" < "$3"
' _ "$SCRIPT" "$KEY" "$work/authorized_keys" 2>/dev/null)"
status=$?
want="$(printf '%s\n%s' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherKeyOtherKey other@host' "from=\"10.0.10.5\",restrict $KEY")"
if [ "$status" -eq 0 ] && [ "$out" = "$want" ]; then
    echo "PASS: upsert_key_line replaces the old line for the same key and keeps others"
    pass=$((pass + 1))
else
    echo "FAIL: upsert_key_line output wrong (exit $status)"
    echo "  output: $out"
    echo "  wanted: $want"
    fail=$((fail + 1))
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

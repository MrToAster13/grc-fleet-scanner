#!/usr/bin/env bash
# test_harness_skips.sh: the pre-commit hook runs every shell harness, and the
# hook supports a Windows Git Bash checkout. Git for Windows ships no visudo,
# and MSYS `ln -s` copies files by default. On such a host the two harnesses
# that need those tools print a SKIP line and exit 0, so the hook does not
# block every commit. When CI is set, a missing tool still fails, so CI on
# ubuntu keeps enforcing both checks.
#
# The visudo cases point GRC_VISUDO at a path that does not exist. The ln
# cases put a fake `ln` first on PATH that copies, as MSYS `ln -s` does.
#
# Run:
#   bash tests/shell/test_harness_skips.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pass=0
fail=0

check() {
    local desc="$1" ok="$2" detail="${3:-}"
    if [ "$ok" = yes ]; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc"
        [ -n "$detail" ] && echo "  $detail"
        fail=$((fail + 1))
    fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 1. no visudo outside CI: the integrity harness exits 0 with a SKIP line.
out="$(env -u CI GRC_VISUDO="$work/no-visudo" bash "$HERE/test_target_setup_integrity.sh" 2>&1)"
rc=$?
check "integrity harness exits 0 with no visudo outside CI" \
    "$([ "$rc" -eq 0 ] && echo yes || echo no)" "rc=$rc; $(printf '%s' "$out" | grep -E 'FAIL|visudo')"
check "integrity harness prints a SKIP line for visudo" \
    "$(printf '%s' "$out" | grep -q '^SKIP: visudo' && echo yes || echo no)" "$(printf '%s' "$out" | grep visudo)"

# 2. no visudo under CI: the integrity harness still fails.
out="$(CI=true GRC_VISUDO="$work/no-visudo" bash "$HERE/test_target_setup_integrity.sh" 2>&1)"
rc=$?
check "integrity harness fails with no visudo when CI is set" \
    "$([ "$rc" -ne 0 ] && echo yes || echo no)" "rc=$rc"
check "integrity harness prints a FAIL line for visudo under CI" \
    "$(printf '%s' "$out" | grep -q '^FAIL: visudo' && echo yes || echo no)" "$(printf '%s' "$out" | grep visudo)"

# A fake ln that copies instead of linking, as MSYS ln -s does by default.
mkdir -p "$work/fakebin"
cat > "$work/fakebin/ln" <<'EOF'
#!/usr/bin/env bash
# Drop the options, then copy the target to the link name.
args=()
for a in "$@"; do
    case "$a" in -*) ;; *) args+=("$a") ;; esac
done
rm -f "${args[1]}"
cp "${args[0]}" "${args[1]}"
EOF
chmod +x "$work/fakebin/ln"

# 3. ln -s copies outside CI: the install-links harness exits 0 with a SKIP line.
out="$(env -u CI PATH="$work/fakebin:$PATH" bash "$HERE/test_install_links.sh" 2>&1)"
rc=$?
check "install-links harness exits 0 when ln -s copies, outside CI" \
    "$([ "$rc" -eq 0 ] && echo yes || echo no)" "rc=$rc; $(printf '%s' "$out" | grep -E 'FAIL' | head -3)"
check "install-links harness prints a SKIP line when ln -s copies" \
    "$(printf '%s' "$out" | grep -q '^SKIP: ln -s' && echo yes || echo no)" "$(printf '%s' "$out" | head -3)"

# 4. ln -s copies under CI: the install-links harness fails.
out="$(CI=true PATH="$work/fakebin:$PATH" bash "$HERE/test_install_links.sh" 2>&1)"
rc=$?
check "install-links harness fails when ln -s copies and CI is set" \
    "$([ "$rc" -ne 0 ] && echo yes || echo no)" "rc=$rc"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

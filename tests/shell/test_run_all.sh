#!/usr/bin/env bash
# test_run_all.sh: tests/shell/run-all.sh is the one entry point for the shell
# harnesses (ELI-719). It runs every test_*.sh in a directory, keeps going
# past a failure, and exits non-zero when any harness fails or none exist.
# AGENTS.md, tests/README.md, CI and the pre-commit hook all call it.
#
# The run-all cases point run-all.sh at a temp dir of stub harnesses, so this
# file never runs itself or the real harnesses.
#
# Run:
#   bash tests/shell/test_run_all.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN_ALL="$HERE/run-all.sh"

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

stub() {   # stub DIR NAME EXIT_CODE: a harness that logs its run and exits
    printf '#!/usr/bin/env bash\necho ran >> "%s/%s.log"\nexit %s\n' "$1" "$2" "$3" > "$1/$2"
}

# 1. every harness passes: exit 0 and each one ran.
mkdir -p "$work/ok"
stub "$work/ok" test_a.sh 0
stub "$work/ok" test_b.sh 0
: > "$work/ok/helper.sh"   # not test_*.sh, never run
out="$(bash "$RUN_ALL" "$work/ok" 2>&1)"; rc=$?
check "all harnesses pass: exit 0" "$([ "$rc" -eq 0 ] && echo yes || echo no)" "exit $rc: $out"
check "all harnesses pass: each test_*.sh ran" \
    "$([ -f "$work/ok/test_a.sh.log" ] && [ -f "$work/ok/test_b.sh.log" ] && echo yes || echo no)" "$out"

# 2. one harness fails: exit 1, the failure is named, the rest still run.
mkdir -p "$work/mixed"
stub "$work/mixed" test_a.sh 1
stub "$work/mixed" test_b.sh 0
out="$(bash "$RUN_ALL" "$work/mixed" 2>&1)"; rc=$?
check "a failing harness: exit 1" "$([ "$rc" -eq 1 ] && echo yes || echo no)" "exit $rc: $out"
check "a failing harness: named in the output" \
    "$(printf '%s' "$out" | grep -q 'FAILED.*test_a.sh' && echo yes || echo no)" "$out"
check "a failing harness: later harnesses still run" \
    "$([ -f "$work/mixed/test_b.sh.log" ] && echo yes || echo no)" "$out"

# 3. no harnesses at all is a failure, not a silent pass.
mkdir -p "$work/empty"
out="$(bash "$RUN_ALL" "$work/empty" 2>&1)"; rc=$?
check "no harnesses: exit 1" "$([ "$rc" -eq 1 ] && echo yes || echo no)" "exit $rc: $out"

# 4. with no argument it runs the harnesses next to it (the real set).
real_count="$(ls "$HERE"/test_*.sh | wc -l)"
listed="$(grep -c '^  test_' <<<"$(bash "$RUN_ALL" --list 2>&1)")"
check "default dir is tests/shell: --list names every test_*.sh" \
    "$([ "$listed" -eq "$real_count" ] && echo yes || echo no)" "listed $listed of $real_count"

# 5. every documented or automated check calls the same entry point.
for f in AGENTS.md tests/README.md .github/workflows/tests.yml .githooks/pre-commit; do
    check "$f calls tests/shell/run-all.sh" \
        "$(grep -q 'tests/shell/run-all.sh' "$REPO/$f" && echo yes || echo no)"
done
# CI must not keep its own per-file list next to run-all.sh.
check "tests.yml runs no single shell harness directly" \
    "$(grep -qE 'bash tests/shell/test_' "$REPO/.github/workflows/tests.yml" && echo no || echo yes)"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

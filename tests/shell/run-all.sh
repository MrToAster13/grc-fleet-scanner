#!/usr/bin/env bash
# run-all.sh: run every shell harness (tests/shell/test_*.sh) and fail if any
# fails. This is the one entry point AGENTS.md, tests/README.md, CI and the
# pre-commit hook call, so a new harness is picked up everywhere by its name
# alone (ELI-719).
#
# Usage:
#   bash tests/shell/run-all.sh          # run the harnesses next to this file
#   bash tests/shell/run-all.sh DIR      # run the test_*.sh files in DIR
#   bash tests/shell/run-all.sh --list   # print the harnesses it would run
set -uo pipefail

list=0
if [ "${1:-}" = "--list" ]; then
    list=1
    shift
fi
dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

shopt -s nullglob
harnesses=("$dir"/test_*.sh)
shopt -u nullglob

if [ "${#harnesses[@]}" -eq 0 ]; then
    echo "run-all: no test_*.sh harnesses in $dir" >&2
    exit 1
fi

if [ "$list" -eq 1 ]; then
    for h in "${harnesses[@]}"; do echo "  $(basename "$h")"; done
    exit 0
fi

failed=()
for h in "${harnesses[@]}"; do
    name="$(basename "$h")"
    echo "== $name"
    if bash "$h"; then
        :
    else
        failed+=("$name")
    fi
done

echo
if [ "${#failed[@]}" -gt 0 ]; then
    echo "run-all: FAILED ${failed[*]} (${#failed[@]} of ${#harnesses[@]} harnesses)"
    exit 1
fi
echo "run-all: all ${#harnesses[@]} harnesses passed"

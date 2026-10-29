#!/usr/bin/env bash
# test_grc_report.sh: shell-level coverage for bin/grc-report's choice of run
# (ELI-633). AC1: it opens the newest run directory that has a report.html,
# skipping newer run dirs left behind by a failed run. AC2: when no run has a
# report.html it exits 1 with one error line and prints no path.
#
# Why this lives outside the pytest suite: grc-report is bash, and its only
# inputs are a directory tree and the environment. Nothing in it needs a
# target host or the Python package, so each case builds a fake output dir
# under mktemp and runs the real script against it.
#
# Nothing opens. The open branch runs only when DISPLAY or WAYLAND_DISPLAY is
# set, so the headless cases unset both. The open-branch case puts a stub
# xdg-open first on PATH; it appends its argument to a log instead of opening
# anything.
#
# Run:
#   bash tests/shell/test_grc_report.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../../bin/grc-report"

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

# Stub opener: records the path it was asked to open, opens nothing.
mkdir -p "$work/stubs"
cat > "$work/stubs/xdg-open" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$1" >> "$(dirname "$0")/opened.log"
STUB
chmod +x "$work/stubs/xdg-open"

# run_grc_report DIR [ENV...]: runs grc-report -o DIR with a clean display
# environment (plus any extra VAR=value args) and the stub opener first on
# PATH. Sets rc, so_out (stdout) and se_out (stderr).
run_grc_report() {
    local dir="$1"; shift
    env -u DISPLAY -u WAYLAND_DISPLAY PATH="$work/stubs:$PATH" "$@" \
        bash "$SCRIPT" -o "$dir" >"$work/stdout" 2>"$work/stderr"
    rc=$?
    so_out="$(cat "$work/stdout")"
    se_out="$(cat "$work/stderr")"
}

# --- AC1 fixture: an older run with a report, a newer failed run without ---- #
ac1="$work/ac1"
mkdir -p "$ac1/runs/20260101T000000Z-aaaaaa" "$ac1/runs/20260102T000000Z-bbbbbb"
: > "$ac1/runs/20260101T000000Z-aaaaaa/report.html"
: > "$ac1/runs/20260102T000000Z-bbbbbb/arf.xml"   # failed run: no report.html

run_grc_report "$ac1"
want="$ac1/runs/20260101T000000Z-aaaaaa/report.html"
check "AC1 headless: skips the newer run with no report and prints the older report path" \
    $([ "$rc" -eq 0 ] && [ "$so_out" = "$want" ] && echo yes || echo no) \
    "exit $rc, stdout '$so_out', wanted '$want'"

# --- AC1 open branch: display set, stub opener receives the same path ------- #
rm -f "$work/stubs/opened.log"
run_grc_report "$ac1" DISPLAY=:99
# The opener runs in the background; wait up to 5s for its log line.
for _ in $(seq 50); do
    [ -s "$work/stubs/opened.log" ] && break
    sleep 0.1
done
opened="$(cat "$work/stubs/opened.log" 2>/dev/null || true)"
check "AC1 display: hands the older report path to the opener" \
    $([ "$rc" -eq 0 ] && [ "$opened" = "$want" ] && echo yes || echo no) \
    "exit $rc, opener got '$opened', wanted '$want'"
rm -f "$work/stubs/opened.log"

# --- AC1 guard: the newest run wins when it does have a report -------------- #
both="$work/both"
mkdir -p "$both/runs/20260101T000000Z-aaaaaa" "$both/runs/20260102T000000Z-bbbbbb"
: > "$both/runs/20260101T000000Z-aaaaaa/report.html"
: > "$both/runs/20260102T000000Z-bbbbbb/report.html"
run_grc_report "$both"
want_newest="$both/runs/20260102T000000Z-bbbbbb/report.html"
check "AC1 guard: prefers the newest run when it has a report" \
    $([ "$rc" -eq 0 ] && [ "$so_out" = "$want_newest" ] && echo yes || echo no) \
    "exit $rc, stdout '$so_out', wanted '$want_newest'"

# --- AC2 fixture: every run is missing its report.html ---------------------- #
ac2="$work/ac2"
mkdir -p "$ac2/runs/20260101T000000Z-aaaaaa" "$ac2/runs/20260102T000000Z-bbbbbb"
: > "$ac2/runs/20260102T000000Z-bbbbbb/arf.xml"

run_grc_report "$ac2"
check "AC2: exits 1 when no run has a report.html" \
    $([ "$rc" -eq 1 ] && echo yes || echo no) "exit $rc, wanted 1"
check "AC2: prints no path on stdout" \
    $([ -z "$so_out" ] && echo yes || echo no) "stdout '$so_out'"
check "AC2: one error line on stderr names the output dir" \
    $(printf '%s' "$se_out" | grep -qF "no run under $ac2/runs has a report.html" && echo yes || echo no) \
    "stderr '$se_out'"
check "AC2: stderr is exactly one line" \
    $([ "$(wc -l < "$work/stderr")" -eq 1 ] && echo yes || echo no) \
    "stderr '$se_out'"

# --- ELI-717: output_dir from the config file -------------------------------- #
# run_grc_report_in CWD [ARGS...]: runs grc-report from CWD with the given
# arguments and no -o of its own. Sets rc, so_out and se_out.
run_grc_report_in() {
    local cwd="$1"; shift
    (cd "$cwd" && env -u DISPLAY -u WAYLAND_DISPLAY PATH="$work/stubs:$PATH" \
        bash "$SCRIPT" "$@" >"$work/stdout" 2>"$work/stderr")
    rc=$?
    so_out="$(cat "$work/stdout")"
    se_out="$(cat "$work/stderr")"
}

cfgd="$work/cfgd"
mkdir -p "$cfgd/cwd" "$cfgd/audits/runs/20260101T000000Z-aaaaaa" "$cfgd/etc"
: > "$cfgd/audits/runs/20260101T000000Z-aaaaaa/report.html"
want_cfg="$cfgd/audits/runs/20260101T000000Z-aaaaaa/report.html"
cat > "$cfgd/etc/config.yaml" <<EOF
scope:
  cidrs: ["10.0.10.0/24"]
output_dir: "$cfgd/audits"   # history.db + per-run reports
EOF

run_grc_report_in "$cfgd/cwd" -c "$cfgd/etc/config.yaml"
check "ELI-717: -c CONFIG reads output_dir from the config" \
    $([ "$rc" -eq 0 ] && [ "$so_out" = "$want_cfg" ] && echo yes || echo no) \
    "exit $rc, stdout '$so_out', stderr '$se_out', wanted '$want_cfg'"

cp "$cfgd/etc/config.yaml" "$cfgd/cwd/config.yaml"
run_grc_report_in "$cfgd/cwd"
check "ELI-717: ./config.yaml is read when no -c or -o is given" \
    $([ "$rc" -eq 0 ] && [ "$so_out" = "$want_cfg" ] && echo yes || echo no) \
    "exit $rc, stdout '$so_out', stderr '$se_out', wanted '$want_cfg'"

run_grc_report_in "$cfgd/cwd" -o "$both"
check "ELI-717: -o wins over the config's output_dir" \
    $([ "$rc" -eq 0 ] && [ "$so_out" = "$want_newest" ] && echo yes || echo no) \
    "exit $rc, stdout '$so_out', wanted '$want_newest'"

# Single quotes, no comment, relative path: resolves against the caller's CWD
# the same way grc-run does.
mkdir -p "$cfgd/rel/out/runs/20260101T000000Z-aaaaaa"
: > "$cfgd/rel/out/runs/20260101T000000Z-aaaaaa/report.html"
printf "scope:\n  cidrs: ['10.0.10.0/24']\noutput_dir: './out'\n" > "$cfgd/rel/config.yaml"
run_grc_report_in "$cfgd/rel"
check "ELI-717: a single-quoted relative output_dir resolves from the CWD" \
    $([ "$rc" -eq 0 ] && [ "$so_out" = "./out/runs/20260101T000000Z-aaaaaa/report.html" ] && echo yes || echo no) \
    "exit $rc, stdout '$so_out', stderr '$se_out'"

# A config with no output_dir falls back to ./grc-output.
mkdir -p "$cfgd/noout/grc-output/runs/20260101T000000Z-aaaaaa"
: > "$cfgd/noout/grc-output/runs/20260101T000000Z-aaaaaa/report.html"
printf 'scope:\n  cidrs: ["10.0.10.0/24"]\n' > "$cfgd/noout/config.yaml"
run_grc_report_in "$cfgd/noout"
check "ELI-717: a config without output_dir falls back to ./grc-output" \
    $([ "$rc" -eq 0 ] && [ "$so_out" = "./grc-output/runs/20260101T000000Z-aaaaaa/report.html" ] && echo yes || echo no) \
    "exit $rc, stdout '$so_out', stderr '$se_out'"

# An explicit -c that does not exist is an error, not a silent fallback.
run_grc_report_in "$cfgd/cwd" -c "$cfgd/etc/missing.yaml"
check "ELI-717: a missing -c file exits 1 and names the file" \
    $([ "$rc" -eq 1 ] && printf '%s' "$se_out" | grep -qF "missing.yaml" && echo yes || echo no) \
    "exit $rc, stderr '$se_out'"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

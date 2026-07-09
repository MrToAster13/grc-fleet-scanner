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

# Echo the interpreter inside a venv (POSIX bin/ or Windows Scripts/), or return
# non-zero if it has none yet. One place owns the bin-vs-Scripts convention.
grc_venv_python() {
    if   [ -x "$1/bin/python" ];         then echo "$1/bin/python"
    elif [ -x "$1/Scripts/python.exe" ]; then echo "$1/Scripts/python.exe"
    else return 1; fi
}

# Ensure $GRC_HOME/.venv exists with the deps installed, then export GRC_PY (the
# venv interpreter) and PYTHONPATH (so grc_auditor / smoketest import from the
# repo). This is the "self-bootstrap on first run" step -- no manual venv needed.
grc_ensure_venv() {
    local venv="$GRC_HOME/.venv"
    if ! GRC_PY="$(grc_venv_python "$venv")"; then
        local base
        base="$(grc_base_python)" || grc_die "no python3 on PATH -- install Python 3.10+."
        echo "grc: first run -- creating virtualenv in $venv ..." >&2
        "$base" -m venv "$venv" \
            || grc_die "could not create the venv (try: sudo apt install -y python3-venv)."
        GRC_PY="$(grc_venv_python "$venv")" \
            || grc_die "venv created but no python found inside $venv."
        echo "grc: installing Python dependencies ..." >&2
        "$GRC_PY" -m pip install --quiet --upgrade pip || true
        "$GRC_PY" -m pip install --quiet -r "$GRC_HOME/requirements.txt" \
            || grc_die "pip install of requirements failed."
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

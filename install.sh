#!/usr/bin/env bash
# install.sh: put the grc-* single-word commands on this run host. No root.
#
# It copies the launchers from ./bin into ~/.local/bin and records where this
# repo lives (in ~/.config/grc/env) so the launchers can find the code and build
# their virtualenv on first use. Re-runnable and idempotent. After this, run
# `grc-setup` to build the venv + install nmap.
set -euo pipefail

REPO="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
BIN_SRC="$REPO/bin"
DEST="${GRC_BIN_DIR:-$HOME/.local/bin}"
ENV_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/grc"
ENV_FILE="$ENV_DIR/env"

echo "grc install: repo at $REPO"
[ -d "$BIN_SRC" ] || { echo "install.sh: $BIN_SRC missing -- run this from the repo root." >&2; exit 1; }

mkdir -p "$DEST" "$ENV_DIR"

# Record the repo location for the launchers (owner-only: it's just a path, but
# the config dir is the operator's).
( umask 077; cat > "$ENV_FILE" <<EOF
# Written by grc-fleet-scanner install.sh. Points the grc-* launchers at the repo.
GRC_HOME="$REPO"
EOF
)
echo "grc install: wrote $ENV_FILE (GRC_HOME=$REPO)"

# Copy the launchers + the sourced helper. Leading-underscore files are helpers,
# not commands, so they're installed but not announced.
commands=()
for f in "$BIN_SRC"/*; do
    name="$(basename "$f")"
    cp "$f" "$DEST/$name"
    chmod +x "$DEST/$name"
    case "$name" in _*) ;; *) commands+=("$name") ;; esac
done
echo "grc install: installed ${#commands[@]} commands to $DEST:"
printf '  %s\n' "${commands[@]}"

# PATH check + offer to add DEST to the shell rc.
case ":$PATH:" in
    *":$DEST:"*)
        echo "grc install: $DEST is already on your PATH."
        ;;
    *)
        echo
        echo "grc install: $DEST is NOT on your PATH."
        line="export PATH=\"$DEST:\$PATH\""
        case "${SHELL##*/}" in
            zsh)  rc="$HOME/.zshrc" ;;
            bash) rc="$HOME/.bashrc" ;;
            *)    rc="$HOME/.profile" ;;
        esac
        printf 'Add it to %s now? [y/N] ' "$rc"
        read -r ans || ans=""
        case "$ans" in
            y|Y)
                printf '\n# grc-fleet-scanner\n%s\n' "$line" >> "$rc"
                echo "Added to $rc. Run: source $rc   (or open a new shell)."
                ;;
            *)
                echo "Skipped. Add this line to your shell rc yourself:"
                echo "  $line"
                ;;
        esac
        ;;
esac

echo
echo "grc install: done. Next:"
echo "  grc-setup     # build the venv + deps, and install nmap on this host"
echo "  grc-demo      # render a sample report (offline sanity check)"
echo "  grc-run       # in a dir with config.yaml (scaffolded on first run)"

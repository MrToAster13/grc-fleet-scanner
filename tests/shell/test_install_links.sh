#!/usr/bin/env bash
# test_install_links.sh: install.sh links the launchers instead of copying them
# (ELI-716). AC1: after install, a change to a launcher or to the sourced
# helper in the repo takes effect in the install dir with no reinstall. AC2:
# CI runs this file with the other shell harnesses.
#
# Each case copies install.sh and bin/ into a throwaway repo under mktemp, so
# editing a launcher never touches the real checkout. HOME, XDG_CONFIG_HOME and
# GRC_BIN_DIR all point into the same temp dir, and the install dir goes first
# on PATH so install.sh skips its PATH prompt.
#
# Run:
#   bash tests/shell/test_install_links.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_REPO="$(cd "$HERE/../.." && pwd)"

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

# new_case NAME: fresh fake repo and home for one case. Sets repo, dest, home.
new_case() {
    home="$work/$1/home"
    repo="$work/$1/repo"
    dest="$home/.local/bin"
    mkdir -p "$home" "$repo"
    cp "$REAL_REPO/install.sh" "$repo/"
    cp -R "$REAL_REPO/bin" "$repo/bin"
}

# run_install: runs the fake repo's install.sh. Sets rc and out.
run_install() {
    out="$(HOME="$home" XDG_CONFIG_HOME="$home/.config" GRC_BIN_DIR="$dest" \
        PATH="$dest:$PATH" bash "$repo/install.sh" </dev/null 2>&1)"
    rc=$?
}

# Case 1: every installed name resolves to the repo's own file.
new_case resolve
run_install
check "install.sh exits 0" "$([ "$rc" -eq 0 ] && echo yes || echo no)" "$out"
all_linked=yes
detail=""
for f in "$repo"/bin/*; do
    name="$(basename "$f")"
    got="$(readlink -f "$dest/$name" 2>/dev/null || true)"
    want="$(readlink -f "$f")"
    if [ "$got" != "$want" ]; then
        all_linked=no
        detail="$detail $name->${got:-missing}"
    fi
done
check "every installed file resolves to the repo's bin/ file" "$all_linked" "$detail"

# Case 2: a launcher edited in the repo after install runs as edited.
cat > "$repo/bin/grc-demo" <<'EOF'
#!/usr/bin/env bash
echo "launcher-v2"
EOF
chmod +x "$repo/bin/grc-demo"
got="$("$dest/grc-demo" 2>&1)"
check "a launcher changed in the repo takes effect with no reinstall" \
    "$([ "$got" = launcher-v2 ] && echo yes || echo no)" "got: $got"

# Case 3: the sourced helper edited in the repo reaches an unchanged launcher.
cat > "$repo/bin/_grc-common.sh" <<'EOF'
grc_setup() { :; }
grc_run_tool() { echo "helper-v2 $*"; }
EOF
got="$("$dest/grc-run" 2>&1)"
check "a helper changed in the repo takes effect with no reinstall" \
    "$([ "$got" = "helper-v2 run" ] && echo yes || echo no)" "got: $got"

# Case 4: an old copy-based install is replaced by links on re-run.
new_case upgrade
mkdir -p "$dest"
for f in "$repo"/bin/*; do
    printf '#!/usr/bin/env bash\necho old-copy\n' > "$dest/$(basename "$f")"
    chmod +x "$dest/$(basename "$f")"
done
run_install
check "re-run over old copies exits 0" "$([ "$rc" -eq 0 ] && echo yes || echo no)" "$out"
check "re-run replaces an old copy with a link to the repo" \
    "$([ -L "$dest/grc-run" ] && [ "$(readlink -f "$dest/grc-run")" = "$(readlink -f "$repo/bin/grc-run")" ] && echo yes || echo no)" \
    "$(ls -l "$dest/grc-run")"

# Case 5: a second run is idempotent and leaves the links in place.
run_install
check "a second run exits 0" "$([ "$rc" -eq 0 ] && echo yes || echo no)" "$out"
check "a second run keeps the links" \
    "$([ -L "$dest/grc-run" ] && [ "$(readlink -f "$dest/grc-run")" = "$(readlink -f "$repo/bin/grc-run")" ] && echo yes || echo no)"

# Case 6: a link left by a launcher later removed from the repo is cleaned up
# on re-run, while a link the operator made to something else is left alone.
new_case removed
printf '#!/usr/bin/env bash\necho gone\n' > "$repo/bin/grc-gone"
chmod +x "$repo/bin/grc-gone"
run_install
rm "$repo/bin/grc-gone"
mkdir -p "$home/other"
ln -s "$home/other/missing-tool" "$dest/someone-elses-link"
run_install
check "re-run removes a dangling link into the repo's bin/" \
    "$([ ! -e "$dest/grc-gone" ] && [ ! -L "$dest/grc-gone" ] && echo yes || echo no)"
check "re-run leaves an unrelated dangling link alone" \
    "$([ -L "$dest/someone-elses-link" ] && echo yes || echo no)"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

#!/bin/sh
# Install the current main branch as an Android-native binary in Termux.
# Unlike install.sh (which downloads a tagged Release), this builds the
# newest pushed fix from source with Termux's own Go/Android toolchain.
set -eu
umask 077

REPO="${CHAT_WITH_CLI_REPO:-https://github.com/ifloppy/chat-with-cli.git}"
REF="${CHAT_WITH_CLI_REF:-main}"
fail() { printf 'chat-with-cli Termux source installer: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"; }

[ "$(uname -s)" = Linux ] || fail 'run this script in native Termux on Android'
[ "$(uname -m)" = aarch64 ] || fail 'only Android ARM64 is supported'
case "${PREFIX:-}" in
  /data/data/*/files/usr|/data/user/*/*/files/usr) ;;
  *) fail 'run inside native Termux, not proot-distro, Debian, or regular Linux' ;;
esac
need pkg
need mktemp
need mv
need install
need sha256sum

missing=
command -v git >/dev/null 2>&1 || missing="$missing git"
command -v go >/dev/null 2>&1 || missing="$missing golang"
command -v clang >/dev/null 2>&1 || missing="$missing clang"
if [ -n "$missing" ]; then
  printf 'Installing missing Termux build tools:%s\n' "$missing"
  # Deliberately unquoted: split the controlled package-name list.
  pkg install -y $missing
fi
need git
need go
need clang

INSTALL_DIR="${CHAT_WITH_CLI_INSTALL_DIR:-$PREFIX/bin}"
[ -d "$INSTALL_DIR" ] || fail "destination directory does not exist: $INSTALL_DIR"
DEST="$INSTALL_DIR/chat-with-cli"
[ ! -L "$DEST" ] || fail "refusing to overwrite symlink: $DEST"
[ ! -e "$DEST" ] || [ -f "$DEST" ] || fail "destination is not a regular file: $DEST"

WORK=$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/chat-with-cli-build.XXXXXXXX")
NEW=
cleanup() {
  [ -z "$NEW" ] || rm -f "$NEW"
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

printf 'Cloning %s (ref: %s)...\n' "$REPO" "$REF"
git clone --quiet --depth 1 --branch "$REF" "$REPO" "$WORK/src" ||
  fail "could not fetch ref $REF"
COMMIT=$(git -C "$WORK/src" rev-parse --short=12 HEAD)
printf 'Building commit %s using %s...\n' "$COMMIT" "$(go version)"
cd "$WORK/src"
# Do not fetch a generic Linux Go toolchain into Termux: use the patched
# Android-native compiler provided by pkg install golang.
GOTOOLCHAIN=local CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC=clang \
  go build -trimpath -ldflags='-s -w' -o "$WORK/chat-with-cli" ./cmd/chat-with-cli ||
  fail 'native Android build failed; update Termux golang/clang packages and retry'

# Replace only after cloning and compiling succeed; preserve the previous
# installation if anything fails before the atomic rename.
NEW=$(mktemp "$INSTALL_DIR/.chat-with-cli.new.XXXXXXXX")
install -m 0755 "$WORK/chat-with-cli" "$NEW"
[ ! -L "$DEST" ] || fail "destination became a symlink: $DEST"
mv -f "$NEW" "$DEST"
NEW=
printf 'Installed %s from commit %s\n' "$DEST" "$COMMIT"
printf 'SHA256: %s\n' "$(sha256sum "$DEST" | awk '{print $1}')"
printf 'Existing CWC configuration was left unchanged. Reconnect your agent to use the new binary.\n'

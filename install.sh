#!/bin/sh
set -eu

REPO="${CHAT_WITH_CLI_REPO:-ifloppy/chat-with-cli}"
VERSION="${CHAT_WITH_CLI_VERSION:-latest}"

fail() { printf 'chat-with-cli installer: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

need uname
case "$(uname -s)" in Linux) ;; *) fail 'supported platforms: Linux and Android (Termux)' ;; esac

# Android reports Linux to uname -s. Detect the Termux userspace explicitly;
# never install a glibc Linux binary into its Bionic environment.
OS=linux
case "${TERMUX__PREFIX:-${PREFIX:-}}" in
  /data/data/*/files/usr|/data/user/*/*/files/usr) OS=android ;;
esac
if [ -n "${TERMUX_VERSION:-}" ] || [ -n "${TERMUX_APP__PACKAGE_NAME:-}" ]; then
  OS=android
fi
if [ "$OS" = android ]; then
  TERMUX_PREFIX="${TERMUX__PREFIX:-${PREFIX:-}}"
  [ -n "$TERMUX_PREFIX" ] && [ -d "$TERMUX_PREFIX/bin" ] || fail 'Android installation requires a working Termux PREFIX'
  INSTALL_DIR="${CHAT_WITH_CLI_INSTALL_DIR:-$TERMUX_PREFIX/bin}"
else
  [ -n "${HOME:-}" ] || [ -n "${CHAT_WITH_CLI_INSTALL_DIR:-}" ] || fail 'HOME is unset; set CHAT_WITH_CLI_INSTALL_DIR explicitly'
  INSTALL_DIR="${CHAT_WITH_CLI_INSTALL_DIR:-$HOME/.local/bin}"
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac
[ "$OS" != android ] || [ "$ARCH" = arm64 ] || fail "Android/Termux release binaries currently support ARM64 only (got $ARCH)"

need curl
need sha256sum
need awk
need sed
need mktemp
need install
need mkdir
need mv

if [ "$VERSION" = latest ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=20" \
    | sed -n 's/^[[:space:]]*"tag_name": "\([^"]*\)",.*/\1/p' | sed -n '1p')
  [ -n "$VERSION" ] || fail 'could not resolve the latest GitHub release'
fi

ASSET="chat-with-cli-$OS-$ARCH"
BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP=$(mktemp -d)
NEW=
cleanup() {
  [ -z "$NEW" ] || rm -f "$NEW"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

printf 'Downloading chat-with-cli %s for %s/%s...\n' "$VERSION" "$OS" "$ARCH"
if ! curl -fsSL "$BASE/$ASSET" -o "$TMP/$ASSET"; then
  fail "could not download $ASSET from $VERSION; check that the release publishes this platform"
fi
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
EXPECTED=$(awk -v f="$ASSET" '$2 == f {print $1; exit}' "$TMP/SHA256SUMS")
[ -n "$EXPECTED" ] || fail "$ASSET is missing from SHA256SUMS"
ACTUAL=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || fail 'SHA-256 verification failed'

mkdir -p "$INSTALL_DIR"
DEST="$INSTALL_DIR/chat-with-cli"
[ ! -L "$DEST" ] || fail "refusing to replace symlink: $DEST"
[ ! -e "$DEST" ] || [ -f "$DEST" ] || fail "destination is not a regular file: $DEST"
NEW=$(mktemp "$INSTALL_DIR/.chat-with-cli.new.XXXXXXXX")
install -m 0755 "$TMP/$ASSET" "$NEW"
mv -f "$NEW" "$DEST"
NEW=
printf 'Installed %s\nSHA256: %s\n' "$DEST" "$ACTUAL"
case ":${PATH:-}:" in *":$INSTALL_DIR:"*) ;; *) printf 'Add %s to PATH if needed.\n' "$INSTALL_DIR" ;; esac
printf '\nIt defaults to the community Relay: https://chat-with-cli.iruanp.com\n'
if [ "$OS" = android ]; then
  printf 'Termux setup: mkdir -p "$HOME/projects" && chat-with-cli agent setup --device termux-phone --root "$HOME/projects" --profile read-only\n'
  printf 'Then authorize and connect: chat-with-cli connect --manual-oauth\n'
  printf 'Android does not provide the Linux systemd or desktop Computer Use backends.\n'
else
  printf 'Interactive terminal hub: chat-with-cli ui\n'
  printf 'Nothing was started automatically. You can also run: chat-with-cli agent setup\n'
fi

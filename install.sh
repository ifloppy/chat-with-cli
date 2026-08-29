#!/bin/sh
set -eu

REPO="${CHAT_WITH_CLI_REPO:-ifloppy/chat-with-cli}"
VERSION="${CHAT_WITH_CLI_VERSION:-latest}"
INSTALL_DIR="${CHAT_WITH_CLI_INSTALL_DIR:-${HOME:-}/.local/bin}"

fail() { printf 'chat-with-cli installer: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

need curl
need sha256sum
need awk
need sed
need uname
need mktemp
need install

[ -n "$INSTALL_DIR" ] || fail 'HOME is unset; set CHAT_WITH_CLI_INSTALL_DIR explicitly'
case "$(uname -s)" in Linux) ;; *) fail 'only Linux is currently supported' ;; esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

if [ "$VERSION" = latest ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=20" \
    | sed -n 's/^[[:space:]]*"tag_name": "\([^"]*\)",.*/\1/p' | sed -n '1p')
  [ -n "$VERSION" ] || fail 'could not resolve the latest GitHub release'
fi

ASSET="chat-with-cli-linux-$ARCH"
BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

printf 'Downloading chat-with-cli %s for linux/%s...\n' "$VERSION" "$ARCH"
curl -fsSL "$BASE/$ASSET" -o "$TMP/$ASSET"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
EXPECTED=$(awk -v f="$ASSET" '$2 == f {print $1; exit}' "$TMP/SHA256SUMS")
[ -n "$EXPECTED" ] || fail "$ASSET is missing from SHA256SUMS"
ACTUAL=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || fail 'SHA-256 verification failed'

mkdir -p "$INSTALL_DIR"
DEST="$INSTALL_DIR/chat-with-cli"
[ ! -L "$DEST" ] || fail "refusing to replace symlink: $DEST"
[ ! -e "$DEST" ] || [ -f "$DEST" ] || fail "destination is not a regular file: $DEST"
NEW="$INSTALL_DIR/.chat-with-cli.new.$$"
install -m 0755 "$TMP/$ASSET" "$NEW"
mv -f "$NEW" "$DEST"
printf 'Installed %s\nSHA256: %s\n' "$DEST" "$ACTUAL"
case ":${PATH:-}:" in *":$INSTALL_DIR:"*) ;; *) printf 'Add %s to PATH if needed.\n' "$INSTALL_DIR" ;; esac
printf '\nInteractive terminal hub: chat-with-cli ui\n'
printf 'It defaults to the community Relay: https://chat-with-cli.iruanp.com\n'
printf 'Nothing was started automatically. You can also run: chat-with-cli agent setup\n'

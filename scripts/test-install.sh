#!/bin/sh
# Mock GitHub downloads and uname so the installer can be tested without
# network access, Android hardware, or changes outside a temporary directory.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
trap 'exit 1' HUP INT TERM

mkdir -p "$TMP/mock-bin" "$TMP/releases" "$TMP/linux-home" "$TMP/termux/bin"

cat > "$TMP/mock-bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf '%s\n' "${TEST_ARCH:-x86_64}" ;;
  *) exec /usr/bin/uname "$@" ;;
esac
EOF

cat > "$TMP/mock-bin/curl" <<'EOF'
#!/bin/sh
dest=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) shift; dest="$1" ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
[ -n "$dest" ] || exit 2
name=${url##*/}
[ -f "$TEST_ASSETS_DIR/$name" ] || exit 22
cp "$TEST_ASSETS_DIR/$name" "$dest"
EOF
chmod +x "$TMP/mock-bin/uname" "$TMP/mock-bin/curl"

printf 'linux amd64\n' > "$TMP/releases/chat-with-cli-linux-amd64"
printf 'linux arm64\n' > "$TMP/releases/chat-with-cli-linux-arm64"
printf 'android arm64\n' > "$TMP/releases/chat-with-cli-android-arm64"
(cd "$TMP/releases" && sha256sum chat-with-cli-* > SHA256SUMS)

run_install() {
  env -u PREFIX -u TERMUX_VERSION -u TERMUX__PREFIX -u TERMUX_APP__PACKAGE_NAME \
    PATH="$TMP/mock-bin:$PATH" \
    CHAT_WITH_CLI_VERSION=v0-test \
    TEST_ASSETS_DIR="$TMP/releases" \
    "$@" sh "$ROOT/install.sh"
}
check() {
  cmp "$1" "$2" >/dev/null || { printf 'mismatched file: %s\n' "$2" >&2; exit 1; }
}

# Linux selection and legacy default path.
run_install HOME="$TMP/linux-home" TEST_ARCH=x86_64 > "$TMP/linux.log"
check "$TMP/releases/chat-with-cli-linux-amd64" "$TMP/linux-home/.local/bin/chat-with-cli"

# Termux selection must not accidentally install the Linux ARM64 build.
run_install HOME="$TMP/termux" TERMUX_VERSION=0.119 PREFIX="$TMP/termux" TEST_ARCH=aarch64 > "$TMP/termux.log"
check "$TMP/releases/chat-with-cli-android-arm64" "$TMP/termux/bin/chat-with-cli"
grep -q 'Android does not provide' "$TMP/termux.log"

# Explicit installation directory overrides the Termux default.
mkdir -p "$TMP/other-bin"
run_install HOME="$TMP/termux" TERMUX_VERSION=0.119 PREFIX="$TMP/termux" TEST_ARCH=aarch64 \
  CHAT_WITH_CLI_INSTALL_DIR="$TMP/other-bin" > /dev/null
check "$TMP/releases/chat-with-cli-android-arm64" "$TMP/other-bin/chat-with-cli"

# Unsupported Android architecture fails before any download.
if run_install HOME="$TMP/termux" TERMUX_VERSION=0.119 PREFIX="$TMP/termux" TEST_ARCH=x86_64 > "$TMP/unsupported.log" 2>&1; then
  echo 'Android x86_64 was incorrectly accepted' >&2
  exit 1
fi
grep -q 'support ARM64 only' "$TMP/unsupported.log"

# A missing Android release asset must fail clearly without touching the binary.
mkdir -p "$TMP/missing"
cp "$TMP/releases/SHA256SUMS" "$TMP/missing/SHA256SUMS"
if run_install HOME="$TMP/termux" TERMUX_VERSION=0.119 PREFIX="$TMP/termux" TEST_ARCH=aarch64 \
  TEST_ASSETS_DIR="$TMP/missing" > "$TMP/missing.log" 2>&1; then
  echo 'missing release asset was incorrectly accepted' >&2
  exit 1
fi
grep -q 'check that the release publishes this platform' "$TMP/missing.log"
check "$TMP/releases/chat-with-cli-android-arm64" "$TMP/termux/bin/chat-with-cli"

# Checksum failure must not overwrite the previously installed version.
mkdir -p "$TMP/tampered"
cp "$TMP/releases/"* "$TMP/tampered/"
printf 'tampered\n' >> "$TMP/tampered/chat-with-cli-android-arm64"
if run_install HOME="$TMP/termux" TERMUX_VERSION=0.119 PREFIX="$TMP/termux" TEST_ARCH=aarch64 \
  TEST_ASSETS_DIR="$TMP/tampered" > "$TMP/tampered.log" 2>&1; then
  echo 'tampered download was incorrectly accepted' >&2
  exit 1
fi
grep -q 'SHA-256 verification failed' "$TMP/tampered.log"
check "$TMP/releases/chat-with-cli-android-arm64" "$TMP/termux/bin/chat-with-cli"

# Never replace a symlinked destination.
rm "$TMP/termux/bin/chat-with-cli"
ln -s "$TMP/releases/chat-with-cli-android-arm64" "$TMP/termux/bin/chat-with-cli"
if run_install HOME="$TMP/termux" TERMUX_VERSION=0.119 PREFIX="$TMP/termux" TEST_ARCH=aarch64 > "$TMP/symlink.log" 2>&1; then
  echo 'symlink destination was incorrectly accepted' >&2
  exit 1
fi
grep -q 'refusing to replace symlink' "$TMP/symlink.log"

printf 'Installer tests passed (Linux, Termux, explicit prefix, missing asset, SHA-256, symlink).\n'

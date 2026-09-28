#!/bin/sh
# easylock installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/zlixas/easylock/main/install.sh | sh
#
# Downloads the release archive for this OS/CPU from GitHub, checks it against the
# release's SHA256SUMS, and installs `easylock` into $EASYLOCK_INSTALL_DIR
# (default: ~/.local/bin). Set EASYLOCK_VERSION=v0.2.0 to pin a version.
set -eu

REPO="zlixas/easylock"
VERSION="${EASYLOCK_VERSION:-latest}"
INSTALL_DIR="${EASYLOCK_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf 'easylock-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

case "$(uname -s)" in
  Linux) os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *) die "unsupported OS $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  arm64 | aarch64) arch="aarch64" ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac
asset="easylock-$arch-$os.tar.gz"

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
else
  die "need curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "need sha256sum or shasum to verify the download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset ($VERSION)"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download SHA256SUMS"

expected="$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
[ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
actual="$(sha256 "$tmp/$asset")"
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"
say "checksum OK"

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/easylock-$arch-$os/easylock" "$INSTALL_DIR/easylock"
say "installed $("$INSTALL_DIR/easylock" --version) to $INSTALL_DIR/easylock"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "add it to your PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
say "try:  easylock tui     |  easylock --lang tr --help"

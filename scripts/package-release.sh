#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="$(cargo metadata --no-deps --format-version 1 | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -n1)"
ARCH="$(uname -m)"
OUT_DIR="dist"
PKG_DIR="${OUT_DIR}/proxec-v${VERSION}-linux-${ARCH}"
TARBALL="${OUT_DIR}/proxec-v${VERSION}-linux-${ARCH}.tar.gz"

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

install -Dm755 target/release/proxec "${PKG_DIR}/proxec"
install -Dm644 README.md "${PKG_DIR}/README.md"
install -Dm644 LICENSE "${PKG_DIR}/LICENSE"
install -Dm644 CHANGELOG.md "${PKG_DIR}/CHANGELOG.md"

tar -czf "$TARBALL" -C "$OUT_DIR" "$(basename "$PKG_DIR")"
echo "Created $TARBALL"

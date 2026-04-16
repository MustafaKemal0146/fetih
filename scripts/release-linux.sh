#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "🚀 Linux release hazırlanıyor..."
npm run build

mkdir -p release
PKG_FILE="$(npm pack --pack-destination release | tail -n 1)"

(
  cd release
  sha256sum "$PKG_FILE" > "${PKG_FILE}.sha256"
)

echo "✅ Release paketi hazır: release/${PKG_FILE}"
echo "✅ Checksum hazır: release/${PKG_FILE}.sha256"
echo
echo "Kurulum (Linux):"
echo "  npm install -g ./release/${PKG_FILE}"
echo
echo "Doğrulama:"
echo "  sha256sum -c ./release/${PKG_FILE}.sha256"

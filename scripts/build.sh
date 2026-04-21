#!/usr/bin/env bash
set -e

log()  { echo "  → $*"; }
ok()   { echo "  ✔ $*"; }
fail() { echo "  ✘ $*" >&2; exit 1; }

echo ""
echo "┌─ Build"

log "Installing dependencies..."
npm ci --silent 2>&1 | tail -1 || fail "Dependency install failed"
ok "Dependencies ready"

log "Compiling TypeScript..."
npm run build --silent 2>&1 || fail "Build failed"
ok "Build complete"

echo "└─ Done"
echo ""

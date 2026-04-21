#!/usr/bin/env bash
set -e

log()  { echo "  → $*"; }
ok()   { echo "  ✔ $*"; }
fail() { echo "  ✘ $*" >&2; exit 1; }

echo ""
echo "┌─ Lint"

log "Installing dependencies..."
npm ci --silent 2>&1 | tail -1 || fail "Dependency install failed"
ok "Dependencies ready"

log "Type-checking source..."
npm run lint --silent 2>&1 || fail "Type errors found"
ok "No type errors"

echo "└─ Done"
echo ""

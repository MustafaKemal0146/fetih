#!/usr/bin/env bash
set -e

log()  { echo "  → $*"; }
ok()   { echo "  ✔ $*"; }
fail() { echo "  ✘ $*" >&2; exit 1; }

echo ""
echo "┌─ Test"

log "Installing dependencies..."
npm ci --silent 2>&1 | tail -1 || fail "Dependency install failed"
ok "Dependencies ready"

log "Running tests..."
npm test --silent 2>&1 || fail "Tests failed"
ok "All tests passed"

echo "└─ Done"
echo ""

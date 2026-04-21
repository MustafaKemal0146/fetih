#!/usr/bin/env bash
set -e

log()  { echo "  → $*"; }
ok()   { echo "  ✔ $*"; }
fail() { echo "  ✘ $*" >&2; exit 1; }

echo ""
echo "┌─ Security Audit"

log "Installing dependencies..."
npm ci --silent 2>&1 | tail -1 || fail "Dependency install failed"
ok "Dependencies ready"

log "Scanning for vulnerabilities (high+)..."
npm audit --audit-level=high 2>&1 || fail "High-severity vulnerabilities found"
ok "No high-severity vulnerabilities"

echo "└─ Done"
echo ""

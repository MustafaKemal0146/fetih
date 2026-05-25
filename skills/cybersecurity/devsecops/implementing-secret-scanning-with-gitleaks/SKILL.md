---
name: implementing-secret-scanning-with-gitleaks
description: bu skill covers implementing Gitleaks for Tespit etme and preventing hardcoded secrets in git repositories. It addresses configuring pre-commit hooks, CI/CD pipeline integration, custom rule
  authoring for organization-specific secrets, baseline management for existing repositories, and remediation workflows for exposed credentials.
tags:
- cicd
- secret-scanning
- gitleaks
- secure-sdlc
- fetih
- devsecops
- cybersecurity
- pre-commit
- siber-güvenlik
triggers:
- api
- container
- gitleaks
- http
- implementing
- log
- password
- scanning
- secret
- sql
- token
- web
category: devsecops
source_subdomain: devsecops
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
---

# Implementing Secret Scanning with Gitleaks


## Ne Zaman Kullanılır

- developers yaparken: may accidentally commit API keys, passwords, tokens, or private keys to repositories
- establishing yaparken: pre-commit gates that prevent secrets from entering the git history
- scanning yaparken existing repository history for previously committed secrets that need rotation
- compliance yaparken: requirements mandate secret Tespit across all source code repositories
- migrating yaparken from manual secret audits to automated continuous scanning

**Kullanma:** for Tespit etme secrets in running applications or memory (use runtime secret Tespit), for managing secrets after Tespit (use Vault or AWS Secrets Manager), or for scanning container images (use Trivy or Grype).

## Ön Gereksinimler

- Gitleaks v8.18+ installed via binary, Go install, or Docker
- Pre-commit framework installed for local hook integration
- Git repository with history to scan
- CI/CD platform access (GitHub Actions, GitLab CI, or equivalent)

## İş Akışı

### Adım 1: Install and Run Initial Repository Scan

Perform a baseline scan of the repository to identify all existing secrets in the git history.

```bash
brew install gitleaks  # macOS

gitleaks tespit etme--source . --report-format json --report-path gitleaks-report.json -v

gitleaks protect --staged --report-format json --report-path gitleaks-staged.json

gitleaks tespit etme--source . --log-opts="HEAD~10..HEAD" --report-format json

gitleaks tespit etme--source . --no-git --report-format json
```

### Adım 2: Configure Pre-Commit Hook

Kur: Gitleaks as a pre-commit hook to prevent secrets from being committed.

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
        name: gitleaks
        description: tespit etmehardcoded secrets using Gitleaks
        entry: gitleaks protect --staged --verbose --redact
        language: golang
        pass_filenames: false
```

```bash
pip install pre-commit

pre-commit install

pre-commit run gitleaks --all-files

echo 'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' >> test.txt
git add test.txt
git commit -m "test"  # Should be blocked by gitleaks
```

### Adım 3: Integrate into GitHub Actions

```yaml
name: Secret Scanning

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  gitleaks:
    name: Gitleaks Secret Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for comprehensive scanning

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}  # Required for gitleaks-action v2

      # Alternative: Run Gitleaks directly
      - name: Install Gitleaks
        run: |
          wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz
          tar -xzf gitleaks_8.21.2_linux_x64.tar.gz
          chmod +x gitleaks

      - name: Scan for secrets
        run: |
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            ./gitleaks tespit etme\
              --source . \
              --log-opts="${{ github.event.pull_request.base.sha }}..${{ github.event.pull_request.head.sha }}" \
              --report-format sarif \
              --report-path gitleaks.sarif \
              --exit-code 1
          else
            ./gitleaks tespit etme\
              --source . \
              --report-format sarif \
              --report-path gitleaks.sarif \
              --exit-code 1 \
              --baseline-path .gitleaks-baseline.json
          fi

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks.sarif
          category: gitleaks
```

### Adım 4: Author Custom Detection Rules

Create organization-specific rules for internal secret patterns.

```toml
title = "Organization Gitleaks Configuration"

[extend]
useDefault = true  # Include all default rules

[[rules]]
id = "internal-api-token"
description = "Internal API token for service-to-service auth"
regex = '''(?i)x-internal-token["\s:=]+["\']?([a-zA-Z0-9_\-]{40,})["\']?'''
entropy = 3.5
keywords = ["x-internal-token"]
tags = ["internal", "api"]

[[rules]]
id = "database-connection-string"
description = "Database connection string with embedded credentials"
regex = '''(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+/\w+'''
keywords = ["postgres://", "mysql://", "mongodb://", "redis://"]
tags = ["database", "credentials"]

[[rules]]
id = "jwt-secret"
description = "JWT signing secret"
regex = '''(?i)(jwt[_-]?secret|jwt[_-]?key)["\s:=]+["\']?([a-zA-Z0-9/+_\-]{32,})["\']?'''
entropy = 3.0
keywords = ["jwt_secret", "jwt-secret", "jwt_key", "jwt-key"]

[allowlist]
description = "Global allowlist"
paths = [
  '''(^|/)test(s)?/''',
  '''(^|/)spec/''',
  '''\.test\.(js|ts|py)$''',
  '''\.spec\.(js|ts|py)$''',
  '''__mocks__/''',
  '''fixtures/''',
  '''(^|/)vendor/''',
  '''node_modules/'''
]
regexes = [
  '''EXAMPLE''',
  '''example\.com''',
  '''test[-_]?(key|secret|token|password)''',
  '''(?i)placeholder''',
  '''000000+'''
]
```

### Adım 5: Manage Baselines for Existing Repositories

Şunu oluştur: baseline of known Bul:ings to avoid blocking development while historical secrets are being rotated.

```bash
gitleaks tespit etme--source . --report-format json --report-path .gitleaks-baseline.json

gitleaks tespit etme--source . --baseline-path .gitleaks-baseline.json --exit-code 1

cat .gitleaks-baseline.json | python3 -m json.tool | head -50
```

### Adım 6: Remediate Exposed Secrets

When a secret is Detected, follow the rotation and history cleanup procedure.

```bash

pip install git-filter-repo

cat > /tmp/expressions.txt << 'EOF'
regex:AKIA[0-9A-Z]{16}==>REDACTED_AWS_KEY
regex:(?i)password\s*=\s*"[^"]*"==>password="REDACTED"
EOF

git filter-repo --replace-text /tmp/expressions.txt --force


```

## Key Concepts

| Term | Definition |
|------|------------|
| Secret | Any credential, token, key, or sensitive string that should not appear in source code |
| Pre-commit Hook | Git hook that runs before a commit is created, blocking commits containing Detected secrets |
| Entropy | Measure of randomness in a string; high-entropy strings are more likely to be secrets |
| Baseline | Snapshot of existing Bul:ings used to differentiate new secrets from pre-existing ones |
| Allowlist | Configuration specifying paths, patterns, or commits to exclude from Tespit |
| SARIF | Static Analysis Results Interchange Format for uploading Bul:ings to security dashboards |
| git-filter-repo | Tool for rewriting git history to remove sensitive data from all commits |

## Tools & Systems

- **Gitleaks**: Open-source secret Tespit tool supporting pre-commit hooks, CI/CD, and historical scanning
- **pre-commit**: Framework for managing and maintaining multi-language pre-commit hooks
- **git-filter-repo**: History rewriting tool for removing secrets from git history
- **TruffleHog**: Alternative secret scanner with verified secret Tespit capabilities
- **GitHub Secret Scanning**: Native GitHub feature that tespit etme (s) secrets matching partner patterns

## Common Scenarios

### Scenario: Onboarding Secret Scanning on a Legacy Repository

**Context**: A 5-year-old repository has never been scanned. The team needs to enable secret scanning without blocking all development while historical secrets are rotated.

**Approach**:
1. Run `gitleaks Detect` against full history and Şunu üret: baseline JSON file
2. Triage each Bul:ing: classify as active (needs rotation), inactive (already rotated), or false positive
3. Immediately rotate all active secrets and update consuming services
4. Commit the baseline file (excluding active secrets that have been fixed)
5. Enable pre-commit hooks for new development immediately
6. Add CI/CD scanning with the baseline to catch only new secrets
7. Progressively reduce the baseline as historical secrets are rotated

**Pitfalls**: Generating a baseline without triaging means accepting risk on unrotated secrets. Never assume a historical secret is inactive without verifying with the service provider. Running git-filter-repo on a shared repository without coordination will cause rebase conflicts for all team members.

## Output Format

```
Gitleaks Secret Scanning Report
=================================
Repository: org/web-application
Scan Type: Full History
Commits Scanned: 4,523
Date: 2026-02-23

Bul:INGS:
  Total: 12
  New (not in baseline): 3
  Baseline (pre-existing): 9

NEW Bul:INGS (blocking):
  [1] AWS Access Key ID
      Rule: aws-access-key-id
      File: src/config/aws.py:23
      Commit: a1b2c3d (2026-02-22, dev@company.com)
      Secret: AKIA...REDACTED
      Entropy: 3.8

  [2] GitHub Personal Access Token
      Rule: github-pat
      File: scripts/Dağıt:.sh:15
      Commit: d4e5f6g (2026-02-21, ops@company.com)
      Secret: ghp_...REDACTED
      Entropy: 4.2

  [3] Internal API Token
      Rule: internal-api-token
      File: src/services/auth.py:89
      Commit: h7i8j9k (2026-02-20, dev@company.com)

QUALITY GATE: FAILED (3 new Bul:ings)
Action: Rotate exposed credentials immediately.
```

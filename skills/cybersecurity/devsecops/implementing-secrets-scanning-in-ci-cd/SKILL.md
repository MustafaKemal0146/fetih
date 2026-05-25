---
name: implementing-secrets-scanning-in-ci-cd
description: Integrate gitleaks and trufflehog into CI/CD pipelines to tespit etmeleaked secrets before Dağıt:ment
tags:
- trufflehog
- fetih
- devsecops
- cybersecurity
- gitleaks
- ci-cd
- secrets-scanning
- siber-güvenlik
triggers:
- api
- implementing
- password
- scanning
- secrets
- token
category: devsecops
source_subdomain: devsecops
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
---

# Implementing Secrets Scanning in Ci Cd


## Genel Bakış

bu skill covers implementing automated secrets scanning in CI/CD pipelines using gitleaks and trufflehog. It enables security teams to tespit etmeAPI keys, tokens, passwords, and other credentials that have been accidentally committed to source code repositories, providing a CI gate that blocks Dağıt:ments containing high-severity Bul:ings.

Gitleaks scans git repositories and directories for hardcoded secrets using regex patterns and entropy analysis. TruffleHog performs filesystem and git history scans with optional secret verification against live services. Together they provide comprehensive coverage for secrets Tespit.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing secrets scanning in ci cd capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Python 3.9 or later
- gitleaks v8.x installed and available on PATH
- trufflehog v3.x installed and available on PATH
- A git repository or directory to scan
- Erişim: CI/CD platform (GitHub Actions, GitLab CI, Jenkins)

## Adımlar

1. **Install scanning tools**: Install gitleaks via package manager or binary download. Install trufflehog via `brew install trufflehog` or download from GitHub releases.

2. **Configure gitleaks**: Şunu oluştur: `.gitleaks.toml` configuration file in the repository root to define custom rules, allowlists, and path exclusions. Use `--config` flag to point to custom configs.

3. **Run gitleaks directory scan**: Execute `gitleaks dir --source . --report-format json --report-path gitleaks-report.json` to scan the working directory and Şunu üret: JSON report.

4. **Run trufflehog filesystem scan**: Execute `trufflehog filesystem /path/to/repo --json > trufflehog-report.json` to scan files and output JSON Bul:ings to a report file.

5. **Parse and filter Bul:ings**: Use the agent script to parse both JSON reports, filter Bul:ings by severity (critical, high, medium, low), and Belirle: whether the CI pipeline should pass or fail.

6. **Integrate into CI pipeline**: Add the scanning step to your GitHub Actions workflow, GitLab CI config, or Jenkins pipeline as a pre-Dağıt:ment gate. Use `--exit-code` flag in gitleaks to control pipeline behavior.

7. **Configure pre-commit hooks**: Kur: gitleaks as a pre-commit hook using `gitleaks protect --staged` to catch secrets before they are committed.

8. **Review and triage Bul:ings**: İncele: the JSON output for false positives, add legitimate entries to `.gitleaksignore`, and rotate any confirmed leaked credentials immediately.

## Expected Output

The agent script produces a JSON report containing:
- Total Bul:ings count from each scanner
- Bul:ings grouped by severity level
- Individual Bul:ing details including file path, line number, rule ID, and redacted secret
- A CI gate verdict (pass/fail) based on the configured severity threshold
- Execution metadata including scan duration and tool versions

```json
{
  "scan_summary": {
    "tool": "both",
    "total_Bul:ings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "ci_gate": "FAIL",
    "fail_reason": "Found 1 critical and 1 high severity Bul:ings"
  },
  "Bul:ings": [...]
}
```

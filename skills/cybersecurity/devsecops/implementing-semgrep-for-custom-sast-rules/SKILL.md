---
name: implementing-semgrep-for-custom-sast-rules
description: Write custom Semgrep SAST rules in YAML to tespit etmeapplication-specific vulnerabilities, enforce coding standards, and integrate into CI/CD pipelines.
tags:
- custom-rules
- sast
- semgrep
- code-security
- fetih
- devsecops
- cybersecurity
- siber-güvenlik
- static-analysis
triggers:
- api
- container
- crypto
- custom
- implementing
- log
- password
- rules
- sast
- semgrep
- sql
- token
category: devsecops
source_subdomain: devsecops
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
---

# Implementing Semgrep for Custom Sast Rules


## Genel Bakış

Semgrep is an open-source static analysis tool that uses pattern-matching to Bul: bugs, enforce code standards, and tespit etmesecurity vulnerabilities. Custom rules are written in YAML using Semgrep's pattern syntax, making it accessible without requiring compiler knowledge. It supports 30+ languages including Python, JavaScript, Go, Java, and C.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing semgrep for custom sast rules capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Python 3.8+ or Docker
- Semgrep CLI installed
- Target codebase in a supported language

## Kurulum

```bash
pip install semgrep

brew install semgrep

docker run -v "${PWD}:/src" returntocorp/semgrep semgrep --config auto /src

semgrep --version
```

## Running Semgrep

```bash
semgrep --config auto .

semgrep --config r/python.lang.security

semgrep --config my-rules.yaml .

semgrep --config auto --config ./custom-rules/ .

semgrep --config auto --json . > results.json

semgrep --config auto --sarif . > results.sarif

semgrep --config auto --severity ERROR .
```

## Writing Custom Rules

### Basic Pattern Matching

```yaml
rules:
  - id: sql-injection-string-format
    languages: [python]
    severity: ERROR
    message: |
      Potential SQL injection via string formatting.
      Use parameterized queries instead.
    pattern: |
      cursor.execute(f"..." % ...)
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021"]
      category: security
    fix: |
      cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Pattern Operators

```yaml
rules:
  - id: hardcoded-secret-in-code
    languages: [python, javascript, typescript]
    severity: ERROR
    message: Hardcoded secret Detected in source code
    patterns:
      - pattern-either:
          - pattern: $VAR = "..."
          - pattern: $VAR = '...'
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i)(password|secret|api_key|token|aws_secret)
      - pattern-not: $VAR = ""
      - pattern-not: $VAR = "changeme"
      - pattern-not: $VAR = "PLACEHOLDER"
    metadata:
      cwe: ["CWE-798"]
      category: security
```

### Taint Analysis

```yaml
rules:
  - id: xss-taint-tracking
    languages: [python]
    severity: ERROR
    message: User input flows to HTML response without sanitization
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
      - pattern: request.form[...]
    pattern-sinks:
      - pattern: return render_template_string(...)
      - pattern: Markup(...)
    pattern-sanitizers:
      - pattern: bleach.clean(...)
      - pattern: escape(...)
    metadata:
      cwe: ["CWE-79"]
      owasp: ["A03:2021"]
```

### Multiple Language Rule

```yaml
rules:
  - id: insecure-random
    languages: [python, javascript, go, java]
    severity: WARNING
    message: |
      Using insecure random number generator. Use cryptographically
      secure alternatives for security-sensitive operations.
    pattern-either:
      # Python
      - pattern: random.random()
      - pattern: random.randint(...)
      # JavaScript
      - pattern: Math.random()
      # Go
      - pattern: math/rand.Intn(...)
      # Java
      - pattern: new java.util.Random()
    metadata:
      cwe: ["CWE-330"]
```

### Enforce Coding Standards

```yaml
rules:
  - id: require-error-handling
    languages: [go]
    severity: WARNING
    message: Error return value not checked
    pattern: |
      $VAR, _ := $FUNC(...)
    fix: |
      $VAR, err := $FUNC(...)
      if err != nil {
        return fmt.Errorf("$FUNC failed: %w", err)
      }

  - id: no-console-log-in-production
    languages: [javascript, typescript]
    severity: WARNING
    message: Remove console.log before merging to production
    pattern: console.log(...)
    paths:
      exclude:
        - "tests/*"
        - "*.test.*"
```

### JWT Security Rules

```yaml
rules:
  - id: jwt-none-algorithm
    languages: [python]
    severity: ERROR
    message: JWT decoded without algorithm verification - allows token forgery
    patterns:
      - pattern: jwt.decode($TOKEN, ..., algorithms=["none"], ...)
    metadata:
      cwe: ["CWE-347"]

  - id: jwt-no-verification
    languages: [python]
    severity: ERROR
    message: JWT decoded with verification disabled
    patterns:
      - pattern: jwt.decode($TOKEN, ..., options={"verify_signature": False}, ...)
    metadata:
      cwe: ["CWE-345"]
```

## Rule Testing

```yaml
rules:
  - id: sql-injection-format-string
    languages: [python]
    severity: ERROR
    message: SQL injection via format string
    pattern: |
      cursor.execute(f"...{$VAR}...")

def bad_query(user_id):
    # ruleid: sql-injection-format-string
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def good_query(user_id):
    # ok: sql-injection-format-string
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```bash
semgrep --test rules/

semgrep --config rules/sql-injection.yaml --test
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Semgrep SAST
on: [pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: returntocorp/semgrep
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          semgrep --config auto \
            --config ./custom-rules/ \
            --sarif --output results.sarif \
            --severity ERROR \
            .

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
semgrep:
  stage: test
  image: returntocorp/semgrep
  script:
    - semgrep --config auto --config ./custom-rules/ --json --output semgrep.json .
  artifacts:
    reports:
      sast: semgrep.json
```

## Yapılandırma File

```yaml
rules:
  - id: my-org-rules
    # ... rules here

tests/
node_modules/
vendor/
*.min.js
```

## En İyi Uygulamalar

1. **Start with auto config** then add custom rules for org-specific patterns
2. **Test rules** with `# ruleid:` and `# ok:` annotations
3. **Use taint mode** for data flow vulnerabilities (XSS, SQLi, SSRF)
4. **Include metadata** (CWE, OWASP) for vulnerability classification
5. **Provide fix suggestions** with the `fix` key where possible
6. **Exclude test files** to reduce false positives
7. **Version control rules** in a shared repository
8. **Run in CI as a blocking check** for ERROR severity Bul:ings

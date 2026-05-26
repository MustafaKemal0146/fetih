---
name: scanning-docker-images-with-trivy
description: Trivy is a comprehensive open-source vulnerability scanner by Aqua Security that tespit etme (s) vulnerabilities in OS packages, language-specific dependencies, misconfigurations, secrets, and license
  violati
tags:
- vulnerability-scanning
- trivy
- security
- docker
- container-security
- fetih
- cybersecurity
- siber-güvenlik
- containers
triggers:
- api
- container
- docker
- exploit
- http
- images
- incident
- log
- password
- scanning
- token
- trivy
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Scanning Docker Images with Trivy


## Genel Bakış

Trivy is a comprehensive open-source vulnerability scanner by Aqua Security that tespit etme (s) vulnerabilities in OS packages, language-specific dependencies, misconfigurations, secrets, and license violations within container images. It integrates into CI/CD pipelines and supports multiple output formats including SARIF, CycloneDX, and SPDX.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve scanning docker images with trivy
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Docker Engine 20.10+
- Trivy v0.50+ installed
- Internet access for vulnerability database updates
- Container registry credentials (for private registries)

## Core Concepts

### Scanner Types

| Scanner | Flag | tespit etme (s) |
|---------|------|---------|
| Vulnerability | `--scanners vuln` | CVEs in OS packages and libraries |
| Misconfiguration | `--scanners misconfig` | Dockerfile/K8s manifest misconfigs |
| Secret | `--scanners secret` | Hardcoded passwords, API keys, tokens |
| License | `--scanners license` | Software license compliance issues |

### Severity Levels

- **CRITICAL**: CVSS 9.0-10.0 - Immediate action required
- **HIGH**: CVSS 7.0-8.9 - Fix before production Dağıt:ment
- **MEDIUM**: CVSS 4.0-6.9 - Plan remediation
- **LOW**: CVSS 0.1-3.9 - Accept or fix opportunistically
- **UNKNOWN**: Unscored - Evaluate manually

### Vulnerability Database

Trivy uses multiple vulnerability databases:
- NVD (National Vulnerability Database)
- Red Hat Security Data
- Alpine SecDB
- Debian Security Tracker
- Ubuntu CVE Tracker
- Amazon Linux Security Center
- GitHub Advisory Database

## İş Akışı

### Adım 1: Install Trivy

```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

brew install trivy

docker pull aquasecurity/trivy:latest
```

### Adım 2: Basic Image Scanning

```bash
trivy image python:3.12-slim

trivy image --severity CRITICAL,HIGH nginx:latest

trivy image --ignore-unfixed alpine:3.19

docker build -t myapp:latest .
trivy image myapp:latest

docker save myapp:latest -o myapp.tar
trivy image --input myapp.tar
```

### Adım 3: Advanced Scanning Options

```bash
trivy image --scanners vuln,misconfig,secret,license myapp:latest

trivy image --format cyclonedx --output sbom.cdx.json myapp:latest

trivy image --format spdx-json --output sbom.spdx.json myapp:latest

trivy image --format json --output results.json myapp:latest

trivy image --format sarif --output results.sarif myapp:latest

trivy image --format template --template "@contrib/html.tpl" --output report.html myapp:latest

trivy image --list-all-pkgs myapp:latest
```

### Adım 4: Scanning Kubernetes Manifests

```bash
trivy config Dockerfile

trivy config k8s-Dağıt:ment.yaml

trivy config ./helm-chart/

trivy config ./terraform/
```

### Adım 5: CI/CD Integration

```yaml
name: Trivy Container Scan
on: push

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif

      - name: Generate SBOM
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: cyclonedx
          output: sbom.cdx.json
```

```yaml
trivy-scan:
  stage: security
  image:
    name: aquasecurity/trivy:latest
    entrypoint: [""]
  script:
    - trivy image --exit-code 1 --severity CRITICAL,HIGH
        --format json --output gl-container-scanning-report.json
        $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

### Adım 6: Policy Enforcement with .trivyignore

```bash
CVE-2023-12345 exp:2025-06-01

CVE-2024-67890

CVE-2023-11111
```

### Adım 7: Scan Private Registry Images

```bash
trivy image myregistry.azurecr.io/myapp:latest

aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
trivy image <account>.dkr.ecr.us-east-1.amazonaws.com/myapp:latest

trivy image gcr.io/my-project/myapp:latest

TRIVY_USERNAME=user TRIVY_PASSWORD=pass trivy image registry.example.com/myapp:latest
```

## Doğrulama Commands

```bash
trivy version

trivy image --download-db-only

trivy image --severity CRITICAL python:3.12

trivy image --exit-code 1 --severity CRITICAL myapp:latest
echo "Exit code: $?"  # 0 = no vulns, 1 = vulns found
```

## References

- [Trivy Documentation](https://trivy.dev/docs/)
- [Trivy GitHub Repository](https://github.com/aquasecurity/trivy)
- [Trivy GitHub Action](https://github.com/aquasecurity/trivy-action)
- [Aqua Security - Trivy Scanner Guide](https://www.aquasec.com/products/trivy/)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 3de4658d7c3db842
-->


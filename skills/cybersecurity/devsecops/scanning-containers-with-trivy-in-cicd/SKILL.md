---
name: scanning-containers-with-trivy-in-cicd
description: bu skill covers integrating Aqua Security's Trivy scanner into CI/CD pipelines for comprehensive container image vulnerability Tespit. It addresses scanning Docker images for OS package
  and application dependency CVEs, Tespit etme misconfigurations in Dockerfiles, scanning filesystem and git repositories, and establishing severity-based quality gates that block Dağıt:ment of vulnerable
  images.
tags:
- cicd
- vulnerability-scanning
- trivy
- container-security
- fetih
- devsecops
- cybersecurity
- secure-sdlc
- siber-güvenlik
triggers:
- api
- cicd
- container
- containers
- exploit
- hash
- http
- scanning
- trivy
- vulnerability
category: devsecops
source_subdomain: devsecops
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
adapted_for: fetih
---

# Scanning Containers with Trivy in Cicd


## Ne Zaman Kullanılır

- building yaparken Docker container images in CI/CD and needing automated vulnerability scanning before registry push
- establishing yaparken: quality gates that prevent images with critical or high CVEs from reaching production
- compliance yaparken: requirements mandate vulnerability scanning of all container images before Dağıt:ment
- scanning yaparken IaC files (Dockerfiles, Kubernetes manifests) alongside container image scanning
- needing yaparken: a single tool to scan OS packages, language-specific dependencies, and misconfigurations

**Kullanma:** for runtime container security monitoring (use Falco), for scanning running containers in production (use runtime agents), or when only scanning application source code without containerization (use SAST tools).

## Ön Gereksinimler

- Trivy CLI kurulu (v0.50+) or Erişim: aquasecurity/trivy-action GitHub Action
- Docker daemon available in CI/CD for building and scanning images
- Container registry credentials for pulling base images and pushing scanned images
- Trivy vulnerability database accessible (downloaded automatically or cached)

## İş Akışı

### Adım 1: Configure Trivy Scanning in GitHub Actions

Kur: a GitHub Actions workflow that builds a Docker image and scans it with Trivy before pushing to a container registry.

```yaml
name: Container Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
    paths:
      - 'Dockerfile'
      - 'docker-compose*.yml'
      - 'src/**'
      - 'requirements*.txt'
      - 'package*.json'

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t app:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: 'app:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
          ignore-unfixed: true

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
          category: 'trivy-container'

      - name: Run Trivy misconfiguration scanner
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: 'config'
          scan-ref: '.'
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
```

### Adım 2: Scan Dockerfiles for Misconfigurations

Trivy tespit etme (s) common Dockerfile security issues such as running as root, using latest tags, and exposing unnecessary ports.

```bash
trivy config --severity HIGH,CRITICAL ./Dockerfile

trivy config --policy ./security-policies --severity MEDIUM,HIGH,CRITICAL .

```

### Adım 3: Integrate with GitLab CI/CD

```yaml
stages:
  - build
  - scan
  - push

variables:
  TRIVY_CACHE_DIR: .trivycache/

build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker save $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -o image.tar
  artifacts:
    paths:
      - image.tar

trivy-scan:
  stage: scan
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  cache:
    paths:
      - .trivycache/
  script:
    - trivy image
        --input image.tar
        --exit-code 1
        --severity CRITICAL,HIGH
        --ignore-unfixed
        --format json
        --output trivy-report.json
    - trivy image
        --input image.tar
        --severity CRITICAL,HIGH,MEDIUM
        --format table
  artifacts:
    reports:
      container_scanning: trivy-report.json
    paths:
      - trivy-report.json
  allow_failure: false

push:
  stage: push
  needs: [trivy-scan]
  script:
    - docker load -i image.tar
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

### Adım 4: Configure Trivy Ignore and Exception Handling

Manage false positives and accepted risks through Trivy's ignore file and VEX statements.

```yaml
vulnerabilities:
  - id: CVE-2023-44487    # HTTP/2 rapid reset - mitigated at load balancer
    statement: "Mitigated by WAF rate limiting at ingress layer"
    expires: 2026-06-01

  - id: CVE-2024-21626    # runc container escape - patched in base image update
    statement: "Tracked in JIRA-SEC-1234, base image update scheduled"
    expires: 2026-03-15

misconfigurations:
  - id: DS002             # User not set - required for init containers
    paths:
      - "docker/init-container/Dockerfile"
    statement: "Init container requires root for volume permission setup"
```

### Adım 5: Implement Database Caching and Offline Scanning

Cache the Trivy vulnerability database in CI/CD to reduce scan times and enable air-gapped environments.

```yaml
- name: Cache Trivy DB
  uses: actions/cache@v4
  with:
    path: /tmp/trivy-db
    key: trivy-db-${{ hashFiles('.github/workflows/container-security.yml') }}
    restore-keys: trivy-db-

- name: Run Trivy with cached DB
  uses: aquasecurity/trivy-action@0.28.0
  with:
    image-ref: 'app:${{ github.sha }}'
    cache-dir: /tmp/trivy-db
    format: 'json'
    output: 'trivy-results.json'
    severity: 'CRITICAL,HIGH'
    exit-code: '1'
```

```bash
trivy image --download-db-only --cache-dir /path/to/cache
trivy image --skip-db-update --cache-dir /path/to/cache myimage:tag
```

### Adım 6: Generate SBOM and Scan for License Compliance

Use Trivy to generate Software Bill of Materials alongside vulnerability scanning.

```bash
trivy image --format cyclonedx --output sbom.cdx.json app:latest

trivy image --format spdx-json --output sbom.spdx.json app:latest

trivy sbom sbom.cdx.json --severity CRITICAL,HIGH

trivy image --scanners vuln,license --severity HIGH,CRITICAL app:latest
```

## Key Concepts

| Term | Definition |
|------|------------|
| CVE | Common Vulnerabilities and Exposures — standardized identifiers for publicly known security vulnerabilities |
| Vulnerability DB | Trivy's regularly updated database aggregating CVE data from NVD, vendor advisories, and language-specific sources |
| Misconfiguration | Security-relevant configuration issue in Dockerfiles, Kubernetes manifests, or IaC templates |
| SBOM | Software Bill of Materials — complete inventory of all components and dependencies in a container image |
| Ignore Unfixed | Flag to skip CVEs without available patches, reducing noise from vulnerabilities with no actionable fix |
| VEX | Vulnerability Exploitability eXchange — machine-readable statements about whether a vulnerability is exploitable in context |
| Exit Code | Non-zero return code from Trivy when Bul:ings exceed the severity threshold, used to fail CI/CD pipelines |

## Tools & Systems

- **Trivy**: Open-source vulnerability scanner by Aqua Security supporting images, filesystems, repos, and IaC
- **trivy-action**: Official GitHub Action for running Trivy scans in GitHub Actions workflows
- **Trivy Operator**: Kubernetes operator that continuously scans cluster workloads with Trivy
- **Grype**: Alternative image scanner by Anchore for comparison and validation of scan results
- **Harbor**: Container registry with built-in Trivy integration for automatic image scanning on push

## Common Scenarios

### Scenario: Multi-Stage Build with Separate Scan and Push

**Context**: A team builds multi-stage Docker images and needs to scan the final production image before pushing to ECR, while also scanning the build stage for supply chain risks.

**Approach**:
1. Şunu inşa et: Docker image with `--target production` for the final stage
2. Run Trivy with `--severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed` to block on exploitable issues
3. Şunu üret:n SBOM in CycloneDX format and store as a build artifact
4. Upload SARIF results to GitHub Security tab for visibility
5. Only push to ECR if the Trivy scan exits with code 0
6. Tag the pushed image with the scan timestamp and Trivy DB version for audit traceability

**Pitfalls**: Scanning only the final stage misses vulnerable packages that were present in build stages and may have influenced the build. Run `trivy fs` on the build context separately. Caching the Trivy DB too aggressively (weekly) means newly published CVEs take days to appear in scans.

## Output Format

```
Trivy Container Scan Report
=============================
Image: app:a1b2c3d4
Base Image: python:3.12-slim-bookworm
Scan Date: 2026-02-23
DB Version: 2026-02-23T00:15:00Z

VULNERABILITY SUMMARY:
  Total: 47
  Critical: 2
  High: 5
  Medium: 18
  Low: 22
  Unfixed: 8 (excluded from gate)

CRITICAL Bul:INGS:
  CVE-2025-12345  libssl3    3.0.11-1  3.0.13-1  OpenSSL buffer overflow
  CVE-2025-67890  curl       7.88.1-10 7.88.1-12 curl HSTS bypass

HIGH Bul:INGS:
  CVE-2025-11111  zlib1g     1.2.13    1.2.13.1  zlib heap buffer overflow
  CVE-2025-22222  python3.12 3.12.1    3.12.3    CPython path traversal
  CVE-2025-33333  requests   2.31.0    2.32.0    requests SSRF in redirects

MISCONFIGURATION:
  DS002  [HIGH]   Dockerfile: USER instruction not set (running as root)
  DS026  [MEDIUM] Dockerfile: No HEALTHCHECK defined

QUALITY GATE: FAILED (2 Critical, 5 High Bul:ings)
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 1f4b908a65e6043c
-->


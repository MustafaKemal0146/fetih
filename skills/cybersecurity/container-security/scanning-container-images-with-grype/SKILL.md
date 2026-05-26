---
name: scanning-container-images-with-grype
description: Scan container images for known vulnerabilities using Anchore Grype with SBOM-based matching and configurable severity thresholds.
tags:
- vulnerability-scanning
- anchore
- container-security
- fetih
- sbom
- cybersecurity
- supply-chain
- grype
- siber-güvenlik
triggers:
- container
- exploit
- grype
- http
- images
- incident
- network
- scanning
- vulnerability
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Scanning Container Images with Grype


## Genel Bakış

Grype is an open-source vulnerability scanner from Anchore that Denetle:s container images, filesystems, and SBOMs for known CVEs. It leverages Syft-generated SBOMs to match packages against multiple vulnerability databases including NVD, GitHub Advisories, and OS-specific feeds.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve scanning container images with grype
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Docker or Podman installed
- Grype CLI kurulu (`curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin`)
- Syft CLI (optional, for SBOM generation)
- Network Erişim: pull vulnerability databases

## Core Commands

### Install Grype

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

grype version

brew install grype
```

### Scan Container Images

```bash
grype nginx:latest

grype docker:myapp:1.0

grype docker-archive:image.tar

grype oci-dir:path/to/oci/

grype sif:image.sif

grype dir:/path/to/project
```

### Output Formats

```bash
grype alpine:3.18

grype alpine:3.18 -o json > results.json

grype alpine:3.18 -o cyclonedx

grype alpine:3.18 -o sarif > grype.sarif

grype alpine:3.18 -o template -t /path/to/template.tmpl
```

### Filtering and Thresholds

```bash
grype nginx:latest --fail-on critical

grype nginx:latest --only-fixed

grype nginx:latest --only-notfixed

grype nginx:latest --only-fixed -o json | jq '[.matches[] | select(.vulnerability.severity == "High")]'

grype nginx:latest --explain --id CVE-2024-1234
```

### Working with SBOMs

```bash
syft nginx:latest -o spdx-json > nginx-sbom.json
grype sbom:nginx-sbom.json

grype sbom:bom.json
```

### Yapılandırma File (.grype.yaml)

```yaml
check-for-app-update: false
fail-on-severity: "high"
output: "json"
scope: "squashed"  # or "all-layers"
quiet: false

ignore:
  - vulnerability: CVE-2023-12345
    reason: "False positive - not exploitable in our context"
  - vulnerability: CVE-2023-67890
    fix-state: unknown

db:
  auto-update: true
  cache-dir: "/tmp/grype-db"
  max-allowed-built-age: 120h  # 5 days

match:
  java:
    using-cpes: true
  python:
    using-cpes: true
  javascript:
    using-cpes: false
```

### CI/CD Integration

```yaml
- name: Scan image with Grype
  uses: anchore/scan-action@v4
  with:
    image: "myregistry/myapp:${{ github.sha }}"
    fail-build: true
    severity-cutoff: high
    output-format: sarif
  id: scan

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.scan.outputs.sarif }}
```

```yaml
container_scan:
  stage: test
  image: anchore/grype:latest
  script:
    - grype ${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA} --fail-on high -o json > grype-report.json
  artifacts:
    reports:
      container_scanning: grype-report.json
```

## Database Management

```bash
grype db status

grype db update

grype db delete

grype db list
```

## Key Vulnerability Sources

| Source | Coverage |
|--------|----------|
| NVD | CVEs across all ecosystems |
| GitHub Advisories | Open source package vulnerabilities |
| Alpine SecDB | Alpine Linux packages |
| Amazon Linux ALAS | Amazon Linux AMI |
| Debian Security Tracker | Debian packages |
| Red Hat OVAL | RHEL, CentOS |
| Ubuntu Security | Ubuntu packages |
| Wolfi SecDB | Wolfi/Chainguard images |

## En İyi Uygulamalar

1. **Pin image tags** - Always scan specific digests, not `latest`
2. **Fail on severity** - Set `--fail-on high` or `critical` in CI gates
3. **Use SBOMs** - Generate SBOMs with Syft for reproducible scanning
4. **Suppress false positives** - Use `.grype.yaml` ignore rules with documented reasons
5. **Scan all layers** - Use `--scope all-layers` to catch vulnerabilities in intermediate layers
6. **Automate database updates** - Keep the vulnerability database current in CI runners
7. **Compare scans** - Track vulnerability count over time for regression Tespit

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: b2060f6bc8d52cd6
-->


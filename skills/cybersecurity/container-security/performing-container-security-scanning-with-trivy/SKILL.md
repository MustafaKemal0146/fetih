---
name: performing-container-security-scanning-with-trivy
description: Scan container images, filesystems, and Kubernetes manifests for vulnerabilities, misconfigurations, exposed secrets, and license compliance issues using Aqua Security Trivy with SBOM generation
  and CI/CD integration.
tags:
- vulnerability-scanning
- trivy
- supply-chain
- docker
- container-security
- fetih
- devsecops
- sbom
- cybersecurity
- kubernetes
- siber-güvenlik
triggers:
- container
- incident
- performing
- scanning
- security
- trivy
- vulnerability
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
---

# Performing Container Security Scanning with Trivy


## Genel Bakış

Trivy is an open-source security scanner by Aqua Security that tespit etme (s) vulnerabilities in OS packages and language-specific dependencies, infrastructure-as-code misconfigurations, exposed secrets, and software license issues across container images, filesystems, Git repositories, and Kubernetes clusters. Trivy generates Software Bill of Materials (SBOM) in CycloneDX and SPDX formats for supply chain transparency. bu skill covers comprehensive container image scanning, CI/CD pipeline integration, Kubernetes operator Dağıt:ment, and scan result triage for security operations.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing container security scanning with trivy
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Trivy v0.50+ kurulu (binary, Docker, or Homebrew)
- Docker daemon access for local image scanning
- Container registry credentials for remote image scanning
- CI/CD platform (GitHub Actions, GitLab CI, Jenkins) for pipeline integration
- Kubernetes cluster for Trivy Operator Dağıt:ment (optional)

## Adımlar

### Adım 1: Scan Container Images

Run vulnerability and secret scanning against container images from local builds or remote registries. Configure severity thresholds and ignore unfixed vulnerabilities.

### Adım 2: Generate SBOM

Produce CycloneDX or SPDX SBOM documents from scanned images for supply chain compliance and vulnerability tracking across the software lifecycle.

### Adım 3: Scan IaC and Kubernetes Manifests

tespit etmemisconfigurations in Dockerfiles, Kubernetes YAML, Terraform, and Helm charts using built-in policy checks aligned with CIS benchmarks.

### Adım 4: Integrate into CI/CD

Add Trivy scanning as a pipeline gate that blocks builds with critical/high vulnerabilities, generates SARIF reports for GitHub Advanced Security, and produces JUnit XML for test dashboards.

## Expected Output

JSON/table report listing CVEs with severity, CVSS scores, fixed versions, affected packages, misconfiguration Bul:ings, and exposed secrets with file locations.

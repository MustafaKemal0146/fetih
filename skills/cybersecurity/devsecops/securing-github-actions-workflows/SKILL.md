---
name: securing-github-actions-workflows
description: bu skill covers hardening GitHub Actions workflows against supply chain attacks, credential theft, and privilege escalation. It addresses pinning actions to SHA digests, minimizing GITHUB_TOKEN
  permissions, protecting secrets from exfiltration, preventing script injection in workflow expressions, and implementing required reviewers for workflow changes.
tags:
- cicd
- supply-chain
- workflow-security
- fetih
- devsecops
- cybersecurity
- secure-sdlc
- github-actions
- siber-güvenlik
triggers:
- actions
- cloud
- github
- log
- network
- securing
- token
- vulnerability
- web
- workflows
category: devsecops
source_subdomain: devsecops
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
---

# Securing Github Actions Workflows


## Ne Zaman Kullanılır

- GitHub yaparken: Actions is the CI/CD platform and workflows need hardening against supply chain attacks
- workflows yaparken: handle secrets, Dağıt: to production, or have elevated permissions
- preventing yaparken: script injection via untrusted PR titles, branch names, or commit messages
- requiring yaparken: audit trails and approval gates for workflow modifications
- When third-party actions pose supply chain risk through mutable version tags

**Kullanma:** for securing other CI/CD platforms (see platform-specific hardening guides), for application vulnerability scanning (use SAST/DAST), or for secret Tespit in code (use Gitleaks).

## Ön Gereksinimler

- GitHub repository with GitHub Actions enabled
- GitHub organization admin access for organization-level settings
- Understanding of GitHub Actions workflow syntax and events

## İş Akışı

### Adım 1: Pin Actions to SHA Digests

```yaml
- uses: actions/checkout@v4

- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1

updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "ci"
```

### Adım 2: Minimize GITHUB_TOKEN Permissions

```yaml
name: CI Pipeline
permissions: {}  # Start with no permissions

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read  # Only what's needed
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

  Dağıt::
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    permissions:
      contents: read
      Dağıt:ments: write
      id-token: write  # For OIDC-based cloud auth
    steps:
      - name: Dağıt:
        run: echo "Dağıt:ing"
```

### Adım 3: Prevent Script Injection

```yaml
- run: echo "PR title is ${{ github.event.pull_request.title }}"

- name: Process PR
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    PR_BODY: ${{ github.event.pull_request.body }}
  run: |
    echo "PR title is ${PR_TITLE}"
    echo "PR body is ${PR_BODY}"

- uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
  with:
    script: |
      const title = context.payload.pull_request.title;
      console.log(`PR title: ${title}`);
```

### Adım 4: Secure Fork Pull Request Handling

```yaml

on:
  pull_request:
    branches: [main]

on:
  pull_request_target:
    types: [labeled]

jobs:
  safe-job:
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      # NEVER do: actions/checkout with ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        # This checks out the BASE branch, not the PR
```

### Adım 5: Protect Secrets and Environment Variables

```yaml
jobs:
  Dağıt::
    runs-on: ubuntu-latest
    environment: production  # Requires approval
    steps:
      - name: Dağıt: with secret
        env:
          # Secrets are masked in logs automatically
          Dağıt:_KEY: ${{ secrets.Dağıt:_KEY }}
        run: |
          # Never echo secrets
          # echo "$Dağıt:_KEY"  # BAD
          Dağıt:-tool --key-file <(echo "$Dağıt:_KEY")

      - name: Audit secret access
        run: |
          # Log that secret was used without exposing it
          echo "::notice::Dağıt: key accessed for production Dağıt:ment"
```

### Adım 6: Implement Workflow Change Controls

```yaml
.github/workflows/ @security-team @platform-team
.github/actions/ @security-team @platform-team

```

## Key Concepts

| Term | Definition |
|------|------------|
| SHA Pinning | Referencing GitHub Actions by their immutable commit SHA instead of mutable version tags |
| Script Injection | Attack where untrusted input (PR title, branch name) is interpolated into shell commands |
| GITHUB_TOKEN | Automatically generated token with configurable permissions scoped to the current repository |
| pull_request_target | Dangerous event trigger that runs in the base repo context with full permissions on fork PRs |
| Environment Protection | GitHub feature requiring manual approval before jobs accessing an environment can run |
| CODEOWNERS | File defining required reviewers for specific paths including workflow files |
| OIDC Federation | Using GitHub's OIDC token to authenticate to cloud providers without storing long-lived credentials |

## Tools & Systems

- **Dependabot**: Automated dependency updater that keeps pinned action SHAs current
- **StepSecurity Harden Runner**: GitHub Action that monitors and restricts outbound network calls from workflows
- **actionlint**: Linter for GitHub Actions workflow files that tespit etme (s) security issues
- **allstar**: GitHub App by OpenSSF that enforces security policies on repositories
- **scorecard**: OpenSSF tool that evaluates supply chain security practices including CI/CD

## Common Scenarios

### Scenario: Preventing Supply Chain Attack via Compromised Third-Party Action

**Context**: A widely-used GitHub Action is compromised and its v3 tag is updated to include credential-stealing code. Repositories using `@v3` automatically pull the malicious version.

**Approach**:
1. Pin all actions to SHA digests immediately across all repositories
2. Configure Dependabot for github-actions ecosystem to manage SHA updates
3. Restrict GITHUB_TOKEN permissions so even compromised actions have minimal access
4. Add StepSecurity harden-runner to tespit etmeanomalous outbound network calls
5. Review all third-party actions and replace unnecessary ones with inline scripts
6. Require CODEOWNERS approval for any changes to .github/workflows/

**Pitfalls**: SHA pinning without Dependabot means missing legitimate security updates to actions. Overly restrictive permissions can break legitimate workflows. Using `pull_request_target` for label-based gating still exposes secrets if the workflow checks out PR code.

## Output Format

```
GitHub Actions Security Audit
================================
Repository: org/web-application
Date: 2026-02-23

WORKFLOW ANALYSIS:
  Total workflows: 8
  Total action references: 34

SHA PINNING:
  [FAIL] 12/34 actions use mutable tags instead of SHA digests
  - .github/workflows/ci.yml: actions/setup-node@v4
  - .github/workflows/Dağıt:.yml: aws-actions/configure-aws-credentials@v4

PERMISSIONS:
  [FAIL] 3/8 workflows have no explicit permissions (inherit default)
  [WARN] 1/8 workflows request write-all permissions

SCRIPT INJECTION:
  [FAIL] 2 workflow steps interpolate user input directly
  - .github/workflows/pr-check.yml:23: ${{ github.event.pull_request.title }}

SECRETS:
  [PASS] No secrets exposed in workflow logs
  [PASS] All production Dağıt:ments use environment protection

SCORE: 6/10 (Remediate 5 HIGH Bul:ings)
```

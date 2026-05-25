---
name: Tespit etme-aws-credential-exposure-with-trufflehog
description: Tespit etme exposed AWS credentials in source code repositories, CI/CD pipelines, and configuration files using TruffleHog, git-secrets, and AWS-native Tespit mechanisms to prevent credential
  theft and unauthorized account access.
tags:
- secrets-Tespit
- credential-exposure
- trufflehog
- aws
- fetih
- devsecops
- cloud-security
- cybersecurity
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- alert
- api
- bulut güvenliği
- cloud
- cloud security
- credential
- Tespit etme
- exposure
- hash
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detection Aws Credential Exposure with Trufflehog


## Ne Zaman Kullanılır

- integrating yaparken secrets Tespit into CI/CD pipelines to prevent credential commits reaching production
- performing yaparken a security audit of existing repositories for historically committed AWS credentials
- responding yaparken to an AWS GuardDuty alert about credential usage from an unexpected IP or region
- onboarding yaparken repositories from acquired companies or third-party vendors
- validating yaparken that credential rotation processes have removed all references to old access keys

**Kullanma:** for real-time credential monitoring (use AWS GuardDuty or Amazon Macie), for managing secrets (use AWS Secrets Manager or HashiCorp Vault), or for Tespit etme non-credential sensitive data like PII (use Amazon Macie or DLP tools).

## Ön Gereksinimler

- TruffleHog v3 kurulu (`brew install trufflehog` or `pip install trufflehog`)
- git-secrets installed for pre-commit hook integration (`brew install git-secrets`)
- Erişim: source code repositories (GitHub, GitLab, Bitbucket, or local git repos)
- AWS CLI configured with permissions to check key status (`iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`)
- GitHub or GitLab API token for scanning organization-wide repositories

## İş Akışı

### Adım 1: Install and Configure TruffleHog

Install TruffleHog v3 and verify it can tespit etmethe AWS credential patterns.

```bash
pip install trufflehog

curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

trufflehog --version

trufflehog git https://github.com/trufflesecurity/test_keys --only-verified
```

### Adım 2: Scan Git Repositories for Exposed Credentials

Scan entire git history including all branches and commits for AWS access keys, secret keys, and session tokens.

```bash
trufflehog git file:///path/to/repo --only-verified --json > trufflehog-results.json

trufflehog github --org=your-organization --token=$GITHUB_TOKEN --only-verified

trufflehog git https://github.com/org/repo.git --only-verified --branch=main

trufflehog gitlab --group=your-group --token=$GITLAB_TOKEN --only-verified

trufflehog filesystem /path/to/project --only-verified
```

### Adım 3: Analyze and Validate Detected Credentials

Parse TruffleHog results to identify verified (still-active) credentials versus rotated or test keys.

```bash
cat trufflehog-results.json | python3 -c "
import json, sys
for line in sys.stdin:
    Bul:ing = json.loads(line)
    if 'AWS' in Bul:ing.get('tespit etme (orName)', ''):
        print(f\"tespit etme (or): {Bul:ing['tespit etme (orName)']}\")
        print(f\"Verified: {Bul:ing.get('Verified', False)}\")
        print(f\"Source: {Bul:ing.get('SourceMetadata', {})}\")
        print(f\"Commit: {Bul:ing.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('commit', 'N/A')}\")
        print(f\"File: {Bul:ing.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file', 'N/A')}\")
        print('---')
"

aws iam get-access-key-last-used --access-key-id AKIAIOSFODNN7EXAMPLE

aws iam list-access-keys --user-name target-user \
  --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' --output table
```

### Adım 4: Kur: Pre-Commit Hooks with git-secrets

Prevent credentials from being committed in the first place using git-secrets as a pre-commit hook.

```bash
git secrets --install  # In each repository

git secrets --register-aws

git secrets --add 'AKIA[0-9A-Z]{16}'
git secrets --add 'aws_secret_access_key\s*=\s*.{40}'
git secrets --add 'aws_session_token\s*=\s*.+'

git secrets --scan-history

git secrets --install ~/.git-templates/git-secrets
git config --global init.templateDir ~/.git-templates/git-secrets
```

### Adım 5: Integrate TruffleHog into CI/CD Pipeline

Add TruffleHog scanning as a CI/CD gate to block Dağıt:ments containing exposed credentials.

```yaml
name: Secrets Scan
on: [push, pull_request]

jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified --results=verified
```

```yaml
secrets_scan:
  stage: test
  image: trufflesecurity/trufflehog:latest
  script:
    - trufflehog git file://$CI_PROJECT_DIR --since-commit $CI_COMMIT_BEFORE_SHA --only-verified --fail
  allow_failure: false
```

### Adım 6: Respond to Detected Credential Exposure

Execute incident response procedures when verified credentials are found exposed.

```bash
aws iam update-access-key \
  --user-name compromised-user \
  --access-key-id AKIAEXPOSEDKEY123456 \
  --status Inactive

aws iam create-access-key --user-name compromised-user

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAEXPOSEDKEY123456 \
  --start-time 2026-01-01T00:00:00Z \
  --query 'Events[*].[EventTime,EventName,EventSource,SourceIPAddress]' \
  --output table

aws iam delete-access-key \
  --user-name compromised-user \
  --access-key-id AKIAEXPOSEDKEY123456

java -jar bfg.jar --replace-text credentials.txt repo.git
```

## Key Concepts

| Term | Definition |
|------|------------|
| TruffleHog | Open-source secrets Tespit tool that scans git history, filesystems, and cloud services for exposed credentials using regex patterns and verification APIs |
| Verified Secret | A credential that TruffleHog has confirmed is still active by making an API call to the target service (e.g., AWS STS GetCallerIdentity) |
| git-secrets | AWS Labs pre-commit hook tool that prevents committing strings matching AWS credential patterns to git repositories |
| Access Key Rotation | The practice of regularly replacing AWS access key pairs to limit the window of exposure if a key is compromised |
| BFG Repo Cleaner | Tool for removing sensitive data from git history without rewriting the entire repository, faster than git filter-branch |
| GitHub Secret Scanning | GitHub-native feature that scans public repositories for known credential patterns and notifies the credential provider |

## Tools & Systems

- **TruffleHog v3**: Primary scanning engine supporting git, filesystem, S3, and CI/CD integration with verified credential Tespit
- **git-secrets**: AWS Labs pre-commit hook for preventing credential commits at the developer workstation level
- **BFG Repo Cleaner**: Fast tool for removing credentials from git history after exposure is Detected
- **AWS GuardDuty**: Threat Tespit service that alerts on anomalous usage of AWS credentials from unexpected locations
- **GitHub Advanced Security**: Platform-native secret scanning for GitHub repositories with push protection

## Common Scenarios

### Scenario: Developer Commits AWS Credentials to a Public GitHub Repository

**Context**: GitHub secret scanning notifies that an AWS access key was pushed to a public repository. The key belongs to a developer with production S3 and DynamoDB access.

**Approach**:
1. Immediately deactivate the access key using `aws iam update-access-key --status Inactive`
2. Run `aws cloudtrail lookup-events` filtering by the exposed AccessKeyId to check for unauthorized usage
3. Scan the full repository history with `trufflehog git` to Bul: any other exposed credentials
4. Şunu üret: new access key for the developer and deliver it through Secrets Manager
5. Remove the credential from git history using BFG Repo Cleaner
6. Install git-secrets pre-commit hook on the developer's workstation
7. Add TruffleHog to the repository's CI/CD pipeline to prevent recurrence

**Pitfalls**: Simply deleting the commit or force-pushing does not remove credentials from GitHub's cache or forks. The key must be deactivated at the AWS level immediately. GitHub secret scanning may have already notified AWS, triggering automated key deactivation.

## Output Format

```
AWS Credential Exposure Scan Report
======================================
Scan Target: github.com/acme-corp (42 repositories)
Scan Date: 2026-02-23
Tool: TruffleHog v3.63.0
Mode: Full git history scan with verification

VERIFIED Bul:INGS (Active Credentials):
[CRED-001] AWS Access Key - VERIFIED ACTIVE
  Key ID: AKIA...WXYZ
  Repository: acme-corp/backend-api
  File: Dağıt:/config.env
  Commit: a1b2c3d (2025-08-15)
  Author: developer@acme.com
  IAM User: svc-backend-Dağıt:
  Permissions: S3, DynamoDB, SQS (production)
  Status: CRITICAL - Key active and used from 3 IP addresses
  Action Required: Immediate deactivation and rotation

[CRED-002] AWS Secret Key - VERIFIED ACTIVE
  Repository: acme-corp/data-pipeline
  File: scripts/etl_config.py
  Commit: d4e5f6g (2025-11-22)
  Author: data-engineer@acme.com
  Status: HIGH - Key active, last used 2 days ago

UNVERIFIED Bul:INGS (Potential Credentials):
  Total pattern matches: 15
  Likely test/example keys: 12
  Requires manual review: 3

SUMMARY:
  Repositories scanned: 42
  Commits analyzed: 125,847
  Verified active credentials: 2
  Unverified credential patterns: 15
  Repositories with pre-commit hooks: 8 / 42
```

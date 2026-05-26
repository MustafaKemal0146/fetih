---
name: performing-privileged-account-access-review
description: Conduct systematic reviews of privileged accounts to validate access rights, identify excessive permissions, and enforce least privilege across PAM infrastructure.
tags:
- cybersecurity
- least-privilege
- identity-governance
- access-review
- privileged-accounts
- fetih
- audit
- pam
- compliance
- identity-access-management
- siber-güvenlik
triggers:
- access
- account
- api
- cloud
- http
- incident
- log
- password
- performing
- privileged
- review
- sql
category: identity-access-management
source_subdomain: identity-access-management
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
adapted_for: fetih
---

# Performing Privileged Account Access Review


## Genel Bakış

Privileged Account Access Review is a critical identity governance process that validates whether users with elevated permissions still require their access. This review covers domain admins, service accounts, database administrators, cloud IAM roles, and application-level privileged accounts. Regular access reviews are mandated by SOC 2, PCI DSS, HIPAA, and SOX compliance frameworks, typically required quarterly for high-privilege accounts.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing privileged account access review
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- PAM solution Dağıtılmış (CyberArk, BeyondTrust, Delinea, or equivalent)
- Identity governance platform (SailPoint, Saviynt, or equivalent)
- Complete inventory of privileged accounts across all platforms
- Defined access review policy with SLAs and escalation procedures
- Designated reviewers (account owners, managers, security team)

## Core Concepts

### Privileged Account Categories

| Category | Examples | Risk Level | Review Frequency |
|----------|----------|------------|-----------------|
| Domain Admins | Enterprise Admin, Domain Admin, Schema Admin | Critical | Monthly |
| Service Accounts | SQL service, backup agents, monitoring agents | High | Quarterly |
| Cloud IAM | AWS root, Azure Global Admin, GCP Owner | Critical | Monthly |
| Database Admin | DBA accounts, sa/sys accounts | High | Quarterly |
| Application Admin | App admin roles, API keys with admin scope | Medium | Semi-annually |
| Emergency/Break-glass | Firecall accounts, emergency access | Critical | After each use |

### Four-Pillar Review Framework

```
DISCOVER                    VALIDATE                    REMEDIATE                 MONITOR
    │                           │                           │                       │
    ├─ Enumerate all            ├─ Verify business          ├─ Remove excess        ├─ Continuous
    │  privileged accounts      │  justification            │  privileges           │  monitoring
    │                           │                           │                       │
    ├─ Identify orphaned        ├─ Confirm account          ├─ Disable orphaned     ├─ Anomaly
    │  accounts                 │  ownership                │  accounts             │  Tespit
    │                           │                           │                       │
    ├─ Map permissions to       ├─ Check compliance         ├─ Enforce password     ├─ Session
    │  business roles           │  with policies            │  rotation             │  recording
    │                           │                           │                       │
    └─ Classify by risk         └─ Review last usage        └─ Implement JIT        └─ Audit
       level                       and activity                access                  logging
```

## İş Akışı

### Adım 1: Account Discovery and Inventory

Enumerate all privileged accounts across the environment:

**Active Directory:**
- Domain Admins, Enterprise Admins, Schema Admins groups
- Accounts with AdminCount=1 attribute
- Service accounts with SPN (Service Principal Names)
- Accounts with delegation rights (Unconstrained/Constrained)

**Cloud Platforms:**
- AWS: IAM users/roles with AdministratorAccess, PowerUserAccess, or `iam:*` permissions
- Azure: Global Administrator, Privileged Role Administrator, Security Administrator roles
- GCP: Owner, Editor roles at organization/project level

**Databases:**
- SQL Server: sysadmin, db_owner, securityadmin fixed roles
- Oracle: DBA, SYSDBA, SYSOPER privileges
- PostgreSQL: superuser, createrole, createdb attributes

### Adım 2: Establish Review Criteria

Each privileged account must be evaluated against:

1. **Business Justification**: Does the user's current role require this privilege?
2. **Least Privilege**: Can the task be performed with lower privileges?
3. **Account Activity**: Has the account been active in the last 90 days?
4. **Compliance Status**: Does the account meet password policy, MFA requirements?
5. **Separation of Duties**: Does the access create SoD conflicts?
6. **Ownership**: Is a responsible owner assigned and active?

### Adım 3: Conduct the Review

For each account, the designated reviewer must:

1. Şunu incele: account details, permissions, and last activity date
2. Approve (certify) the access if still required with documented justification
3. Revoke access if no longer needed or the reviewer cannot justify the privilege
4. Flag for investigation if anomalous activity or policy violations are Detected
5. Escalate if the reviewer cannot make a determination

Decision matrix:

| Condition | Action |
|-----------|--------|
| Active user, justified privilege | Certify - maintain access |
| Active user, excessive privilege | Remediate - reduce to least privilege |
| Inactive > 90 days | Disable account, notify owner |
| No owner identified | Disable account, escalate to security |
| SoD conflict Detected | Remediate - reassign or add compensating controls |
| Break-glass account | Verify last use was authorized, reset credentials |

### Adım 4: Remediation and Enforcement

After reviews are completed:

- Revoke access for accounts that were not certified within the SLA period
- Implement automatic revocation for accounts not reviewed within 14 days
- Rotate credentials for all certified privileged accounts
- Convert standing privileges to just-in-time (JIT) access where possible
- Update PAM vault with current account inventory

### Adım 5: Reporting and Documentation

Generate review reports including:

- Total accounts reviewed vs. total in scope
- Certification rate (approved vs. revoked)
- Average review completion time
- Overdue reviews and escalations
- Remediation actions taken
- Comparison with previous review cycle

## Doğrulama Checklist

- [ ] Complete inventory of all privileged accounts documented
- [ ] All accounts assigned to a responsible owner/reviewer
- [ ] Review criteria and decision matrix defined
- [ ] Reviewers completed certification within SLA (14 days)
- [ ] Revoked accounts disabled and credentials rotated
- [ ] Orphaned accounts identified and disabled
- [ ] Service accounts reviewed for least privilege
- [ ] Break-glass accounts audited for authorized use only
- [ ] Review report generated with metrics and trends
- [ ] Remediation tickets created and tracked to completion
- [ ] Evidence preserved for compliance audit

## References

- [NIST SP 800-53 AC-2: Account Management](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-2/)
- [CIS Controls v8 - Control 5: Account Management](https://www.cisecurity.org/controls/account-management)
- [Netwrix PAM Best Practices Guide](https://netwrix.com/en/resources/guides/privileged-account-management-best-practices/)
- [StrongDM PAM Best Practices 2025](https://www.strongdm.com/blog/privileged-access-management-best-practices)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: c1b0e2ab37e33a3a
-->


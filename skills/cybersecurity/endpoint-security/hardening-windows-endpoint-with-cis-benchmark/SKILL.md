---
name: hardening-windows-endpoint-with-cis-benchmark
description: Hardens Windows endpoints using CIS (Center for Internet Security) Benchmark recommendations to reduce attack surface, enforce security baselines, and meet compliance requirements. Use when
  Dağıt:ing new Windows workstations or servers, remediating audit Bul:ings, or establishing organization-wide security baselines. Activates for requests involving Windows hardening, CIS benchmarks, GPO
  security baselines, or endpoint configuration compliance.
tags:
- baseline-configuration
- endpoint-security
- fetih
- endpoint
- cybersecurity
- GPO
- windows-security
- hardening
- siber-güvenlik
- CIS-benchmark
triggers:
- authentication
- benchmark
- cloud
- encryption
- endpoint
- hardening
- log
- network
- password
- vulnerability
- windows
category: endpoint-security
source_subdomain: endpoint-security
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
adapted_for: fetih
---

# Hardening Windows Endpoint with Cis Benchmark


## Ne Zaman Kullanılır

Use bu skill when:
- Dağıt:ing new Windows 10/11 or Server 2019/2022 endpoints that require security hardening
- Establishing organization-wide security baselines using CIS Level 1 or Level 2 profiles
- Remediating Bul:ings from compliance audits (PCI DSS, HIPAA, SOC 2) that reference CIS benchmarks
- Validating existing endpoint configurations against current CIS benchmark versions

**Kullanma:** bu skill for Linux endpoints (use hardening-linux-endpoint-with-cis-benchmark) or for cloud-native workloads that require CIS cloud benchmarks.

## Ön Gereksinimler

- Windows 10/11 Enterprise or Windows Server 2019/2022 target endpoints
- Active Directory Group Policy Management Console (GPMC) for enterprise Dağıt:ment
- CIS-CAT Pro Assessor or CIS-CAT Lite for automated benchmark assessment
- Administrative Erişim: target endpoints or domain controller
- Current CIS Benchmark PDF for the target Windows version (download from cisecurity.org)

## İş Akışı

### Adım 1: Select CIS Benchmark Profile Level

CIS provides two profile levels for Windows endpoints:

**Level 1 (L1) - Corporate/Enterprise Environment**:
- Practical hardening settings that can be applied to most organizations
- Minimal impact on functionality and user experience
- Covers: password policy, audit policy, user rights, security options, Windows Firewall

**Level 2 (L2) - High Security/Sensitive Data**:
- Includes all L1 settings plus additional restrictions
- May impact usability (disabling autorun, restricting remote desktop, enhanced audit logging)
- Appropriate for systems handling PII, PHI, PCI data, or classified information

Select profile based on data classification and risk tolerance of the endpoint.

### Adım 2: Import CIS GPO Baselines

CIS provides pre-built GPO templates (Build Kits) for each benchmark 
```powershell

Import-GPO -BackupGpoName "CIS Microsoft Windows 11 Enterprise v3.0.0 L1" `
  -TargetName "CIS-Win11-L1-Baseline" `
  -Path "C:\CIS-GPO-Backups\Win11-Enterprise" `
  -CreateIfNeeded

New-GPLink -Name "CIS-Win11-L1-Baseline" `
  -Target "OU=Workstations,DC=corp,DC=example,DC=com" `
  -LinkEnabled Yes
```

### Adım 3: Apply Key CIS Benchmark Categories

**Account Policies (Section 1)**:
```
Password Policy:
  - Minimum password length: 14 characters (1.1.4)
  - Maximum password age: 365 days (1.1.3)
  - Password complexity: Enabled (1.1.5)
  - Store passwords using reversible encryption: Disabled (1.1.6)

Account Lockout Policy:
  - Account lockout threshold: 5 invalid logon attempts (1.2.1)
  - Account lockout duration: 15 minutes (1.2.2)
  - Reset account lockout counter after: 15 minutes (1.2.3)
```

**Local Policies - Audit Policy (Section 17)**:
```
Audit Policy Configuration:
  - Audit Credential Validation: Success and Failure (17.1.1)
  - Audit Security Group Management: Success (17.2.5)
  - Audit Logon: Success and Failure (17.5.1)
  - Audit Process Creation: Success (17.6.1)
  - Audit Removable Storage: Success and Failure (17.6.4)
```

**Security Options (Section 2.3)**:
```
  - Interactive logon: Do not display last user name: Enabled (2.3.7.1)
  - Interactive logon: Machine inactivity limit: 900 seconds (2.3.7.3)
  - Network access: Do not allow anonymous enumeration of SAM accounts: Enabled (2.3.10.2)
  - Network security: LAN Manager authentication level: Send NTLMv2 response only (2.3.11.7)
  - UAC: Run all administrators in Admin Approval Mode: Enabled (2.3.17.6)
```

**Windows Firewall (Section 9)**:
```
  - Domain Profile: Firewall state: On (9.1.1)
  - Domain Profile: Inbound connections: Block (9.1.2)
  - Private Profile: Firewall state: On (9.2.1)
  - Public Profile: Firewall state: On (9.3.1)
  - Public Profile: Inbound connections: Block (9.3.2)
```

### Adım 4: Validate with CIS-CAT Assessment

```powershell

.\Assessor-CLI.bat `
  -b "benchmarks\CIS_Microsoft_Windows_11_Enterprise_Benchmark_v3.0.0-xccdf.xml" `
  -p "Level 1 (L1) - Corporate/Enterprise Environment" `
  -rd "C:\CIS-Reports" `
  -nts

```

### Adım 5: Document Exceptions and Compensating Controls

For each CIS recommendation that cannot be applied:
1. Şunu belgele: specific recommendation ID and title
2. State the business justification for the exception
3. Define the compensating control that addresses the residual risk
4. Set a review date (quarterly) to reassess the exception
5. Obtain sign-off from the information security officer

Example exception:
```
Recommendation: 2.3.7.3 - Interactive logon: Machine inactivity limit: 900 seconds
Exception: Kiosk systems in manufacturing floor require 1800 seconds
Compensating Control: Physical badge-Erişim: manufacturing area, CCTV monitoring
Review Date: 2026-06-01
Approved By: CISO
```

### Adım 6: Continuous Compliance Monitoring

Configure recurring CIS-CAT scans via scheduled tasks or SCCM:
```powershell
$action = New-ScheduledTaskAction -Execute "C:\CIS-CAT\Assessor-CLI.bat" `
  -Argument "-b benchmarks\CIS_Win11_v3.0.0-xccdf.xml -p Level1 -rd C:\CIS-Reports -nts"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "CIS-Benchmark-Scan" -Action $action `
  -Trigger $trigger -Principal $principal
```

Feed results into SIEM for drift Tespit and dashboard reporting.

## Key Concepts

| Term | Definition |
|------|-----------|
| **CIS Benchmark** | Consensus-based security configuration guide developed by CIS with input from government, industry, and academia |
| **Level 1 Profile** | Practical security baseline suitable for most organizations with minimal operational impact |
| **Level 2 Profile** | Extended security baseline for high-security environments that may reduce functionality |
| **CIS-CAT** | CIS Configuration Assessment Tool that automates benchmark compliance checking |
| **Build Kit** | Pre-configured GPO templates provided by CIS that implement benchmark recommendations |
| **Scoring** | CIS recommendations are either Scored (compliance-measurable) or Not Scored (best-practice guidance) |

## Tools & Systems

- **CIS-CAT Pro Assessor**: Automated benchmark compliance scanner (requires CIS SecureSuite license)
- **Microsoft Security Compliance Toolkit (SCT)**: Microsoft's own GPO baselines (complementary to CIS)
- **Group Policy Management Console (GPMC)**: Enterprise GPO Dağıt:ment and management
- **LGPO.exe**: Microsoft tool for applying GPOs to standalone (non-domain) systems
- **Nessus/Tenable**: Vulnerability scanner with CIS benchmark audit files

## Common Pitfalls

- **Applying L2 to all endpoints**: Level 2 restrictions (disabling Autoplay, restricting Remote Desktop) break workflows on standard workstations. Reserve L2 for endpoints handling sensitive data.
- **Not testing GPOs in pilot OU**: Dağıt: CIS GPOs to a test OU with representative hardware/software before organization-wide rollout to avoid breaking line-of-business applications.
- **Ignoring CIS benchmark version updates**: CIS benchmarks update with each Windows feature release. Running an outdated benchmark misses new security settings and generates false compliance reports.
- **Forgetting local admin accounts**: CIS benchmarks assume domain-joined endpoints. Standalone systems require LGPO.exe or Microsoft Intune for baseline enforcement.
- **No exception process**: Applying 100% of CIS recommendations is rarely feasible. Without a formal exception process, teams either ignore hardening or break applications.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 2a549a55c2f74986
-->


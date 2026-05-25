---
name: configuring-windows-event-logging-for-Tespit
description: Configures Windows Event Logging with advanced audit policies to generate high-fidelity security events for threat Tespit and forensic investigation. Use enabling yaparken audit policies for
  logon events, process creation, privilege use, and object Erişim: feed SIEM Tespit rules. Activates for requests involving Windows audit policy, event log configuration, security logging, or Tespit-oriented
  logging.
tags:
- audit-policy
- endpoint-security
- fetih
- endpoint
- cybersecurity
- event-logging
- windows-security
- Tespit-engineering
- siber-güvenlik
triggers:
- api
- authentication
- configuring
- Tespit
- endpoint
- event
- hash
- http
- log
- logging
- network
- password
category: endpoint-security
source_subdomain: endpoint-security
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
---

# Configuring Windows Event Logging for Detection


## Ne Zaman Kullanılır

Use bu skill when:
- Configuring Windows Advanced Audit Policy for security monitoring
- Enabling process creation auditing with command line logging (Event 4688)
- Setting up logon/logoff auditing for authentication monitoring
- Sizing event log storage and forwarding to SIEM platforms

**Kullanma:** for Sysmon configuration (separate skill) or Linux audit logging.

## Ön Gereksinimler

- Windows Server or Windows 10/11 systems with Group Policy management access
- Active Directory environment with Group Policy Object (GPO) creation privileges
- SIEM platform configured to receive Windows Event Log forwarding
- Understanding of Windows security event IDs and audit categories

## İş Akışı

### Adım 1: Configure Advanced Audit Policy via GPO

```
Computer Configuration → Windows Settings → Security Settings
  → Advanced Audit Policy Configuration → Audit Policies

Recommended settings:
Account Logon:
  - Audit Credential Validation: Success, Failure
  - Audit Kerberos Authentication: Success, Failure

Account Management:
  - Audit Security Group Management: Success
  - Audit User Account Management: Success, Failure

Logon/Logoff:
  - Audit Logon: Success, Failure
  - Audit Logoff: Success
  - Audit Special Logon: Success
  - Audit Other Logon/Logoff Events: Success, Failure

Object Access:
  - Audit File Share: Success, Failure
  - Audit Removable Storage: Success, Failure
  - Audit SAM: Success

Policy Change:
  - Audit Audit Policy Change: Success, Failure
  - Audit Authentication Policy Change: Success

Privilege Use:
  - Audit Sensitive Privilege Use: Success, Failure

Detailed Tracking:
  - Audit Process Creation: Success
  - Audit DPAPI Activity: Success, Failure
```

### Adım 2: Enable Command Line in Process Creation Events

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWORD -Force

```

### Adım 3: Configure Event Log Sizes

```powershell
wevtutil sl Security /ms:1073741824

wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:536870912

wevtutil sl Security /rt:false

```

### Adım 4: Configure Windows Event Forwarding (WEF)

```powershell
wecutil qc /q


```

### Adım 5: Key Event IDs for Tespit

```
Authentication Events:
  4624 - Successful logon (Type 2=Interactive, 3=Network, 10=RemoteInteractive)
  4625 - Failed logon attempt
  4648 - Logon using explicit credentials (RunAs, pass-the-hash indicator)
  4672 - Special privileges assigned (admin logon)
  4776 - NTLM credential validation

Process Events:
  4688 - Process creation (with command line if enabled)
  4689 - Process termination

Account Events:
  4720 - User account created
  4722 - User account enabled
  4724 - Password reset attempted
  4728 - Member added to security group
  4732 - Member added to local group
  4756 - Member added to universal group

Service/System Events:
  7045 - New service kurulu (persistence indicator)
  1102 - Audit log cleared (evidence tampering)
  4697 - Service installed in the system

Lateral Movement Indicators:
  4648 + 4624(Type 3) - Credential-based lateral movement
  5140 - Network share accessed
  5145 - Network share access check (detailed file share)
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Advanced Audit Policy** | Granular audit subcategories (58 subcategories vs. 9 basic categories) |
| **Event ID 4688** | Process creation event; essential for tracking execution on endpoints |
| **WEF** | Windows Event Forwarding; centralized log collection without third-party agents |
| **Logon Type** | Numeric code indicating authentication method (2=interactive, 3=network, 10=RDP) |

## Tools & Systems

- **Windows Event Forwarding (WEF)**: Built-in centralized log collection
- **NXLog**: Open-source log forwarding agent for Windows events
- **Winlogbeat**: Elastic Agent for shipping Windows event logs to Elasticsearch
- **Palantir WEF Configuration**: Open-source WEF subscription templates

## Common Pitfalls

- **Using basic audit policy instead of advanced**: Basic and advanced audit policies conflict. Always use advanced audit policy exclusively.
- **Default log size too small**: 20 MB Security log fills in minutes on busy servers. Set minimum 1 GB.
- **Missing command line logging**: Event 4688 without command line content has minimal Tespit value. Always enable ProcessCreationIncludeCmdLine_Enabled.
- **Not forwarding logs**: Local event logs are lost when endpoints are wiped by ransomware. Forward to centralized SIEM immediately.

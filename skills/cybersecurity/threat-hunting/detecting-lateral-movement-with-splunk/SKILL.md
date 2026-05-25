---
name: Tespit etme-lateral-movement-with-splunk
description: tespit etmeadversary lateral movement across networks using Splunk SPL queries against Windows authentication logs, SMB traffic, and remote service abuse.
tags:
- siem
- threat-hunting
- splunk
- ta0008
- fetih
- mitre-attack
- cybersecurity
- lateral-movement
- siber-güvenlik
- proactive-detection
triggers:
- anomali tespit
- api
- authentication
- cloud
- Tespit etme
- hash
- hunting
- incident
- lateral
- log
- movement
- network
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detection Lateral Movement with Splunk


## Ne Zaman Kullanılır

- hunting yaparken for adversary movement between compromised systems
- After Tespit etme credential theft to trace subsequent lateral activity
- investigating yaparken unusual authentication patterns across the network
- incident response sırasında to scope the breadth of compromise
- proactively yaparken: hunting for TA0008 (Lateral Movement) techniques

## Ön Gereksinimler

- Splunk Enterprise or Splunk Cloud with Windows event data ingested
- Windows Security Event Logs forwarded (4624, 4625, 4648, 4672, 4768, 4769)
- Sysmon Dağıtılmış for process creation and network connection data
- Network flow data or firewall logs for SMB/RDP/WinRM correlation
- Active Directory user and group membership reference data

## İş Akışı

1. **Define Lateral Movement Scope**: Identify which lateral movement techniques to hunt (RDP, SMB/Admin Shares, WinRM, PsExec, WMI, DCOM, SSH).
2. **Query Authentication Events**: Use SPL to Ara: Type 3 (Network) and Type 10 (RemoteInteractive) logons across the environment.
3. **Build Authentication Graphs**: Map source-to-destination authentication relationships to identify unusual connection patterns.
4. **tespit etmeFirst-Time Relationships**: Identify new source-destination pairs that have not been seen in the historical baseline.
5. **Correlate with Process Activity**: Link authentication events to subsequent process creation on destination hosts.
6. **Identify Anomalous Patterns**: Flag lateral movement to sensitive servers, unusual hours, service account misuse, or rapid multi-host access.
7. **Report and Contain**: Document lateral movement path, affected systems, and coordinate containment response.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1021 | Remote Services (parent technique) |
| T1021.001 | Remote Desktop Protocol (RDP) |
| T1021.002 | SMB/Windows Admin Shares |
| T1021.003 | Distributed COM (DCOM) |
| T1021.004 | SSH |
| T1021.006 | Windows Remote Management (WinRM) |
| T1570 | Lateral Tool Transfer |
| T1047 | Windows Management Instrumentation |
| T1569.002 | Service Execution (PsExec) |
| Logon Type 3 | Network logon (SMB, WinRM, mapped drives) |
| Logon Type 10 | Remote Interactive (RDP) |
| Event ID 4624 | Successful logon |
| Event ID 4648 | Explicit credential logon (runas, PsExec) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Splunk Enterprise | SIEM for log aggregation and SPL queries |
| Splunk Enterprise Security | Threat Tespit and notable events |
| Windows Event Forwarding | Centralize Windows logs |
| Sysmon | Detailed process and network telemetry |
| BloodHound | AD attack path analysis |
| PingCastle | AD security assessment |

## Common Scenarios

1. **PsExec Lateral Movement**: Adversary uses PsExec to execute commands on remote systems via SMB, generating Type 3 logon with ADMIN$ share access.
2. **RDP Pivoting**: Attacker RDPs to internal systems using stolen credentials, creating Type 10 logon events.
3. **WMI Remote Execution**: Adversary uses WMIC process call create to spawn processes on remote hosts.
4. **WinRM PowerShell Remoting**: Attacker uses Enter-PSSession or Invoke-Command to execute code on remote systems.
5. **Pass-the-Hash via SMB**: Compromised NTLM hashes used to authenticate to remote systems without knowing the plaintext password.

## Output Format

```
Hunt ID: TH-LATMOV-[DATE]-[SEQ]
Movement Type: [RDP/SMB/WinRM/WMI/DCOM/PsExec]
Source Host: [Hostname/IP]
Destination Host: [Hostname/IP]
Account Used: [Username]
Logon Type: [3/10/other]
First Seen: [Timestamp]
Event Count: [Number of events]
Risk Level: [Critical/High/Medium/Low]
Lateral Movement Path: [A -> B -> C -> D]
```

---
name: Tespit etme-pass-the-ticket-attacks
description: tespit etmeKerberos Pass-the-Ticket (PtT) attacks by analyzing Windows Event IDs 4768, 4769, and 4771 for anomalous ticket usage patterns in Splunk and Elastic SIEM
tags:
- threat-hunting
- threat-Tespit
- splunk
- credential-theft
- elastic
- kerberos
- pass-the-ticket
- fetih
- cybersecurity
- windows-security
- active-directory
- siber-güvenlik
triggers:
- alert
- anomali tespit
- attacks
- authentication
- Tespit etme
- encryption
- endpoint
- hunting
- incident
- log
- pass
- password
category: threat-hunting
source_subdomain: threat-Tespit
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
---

# Detection Pass the Ticket Attacks


## Genel Bakış

Pass-the-Ticket (PtT) is a credential theft technique (MITRE ATT&CK T1550.003) where adversaries steal Kerberos tickets (TGT or TGS) from one system and replay them on another to authenticate without knowing the user's password. bu skill teaches Tespit of PtT attacks by correlating Windows Security Event IDs 4768 (TGT request), 4769 (TGS request), and 4771 (pre-authentication failure) for anomalies such as ticket reuse across different hosts, RC4 encryption downgrades, and unusual service ticket request volumes.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme pass the ticket attacks
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Windows Domain Controller with advanced audit policy enabled (Audit Kerberos Authentication Service, Audit Kerberos Service Ticket Operations)
- Splunk or Elastic SIEM ingesting Windows Security event logs
- Sysmon Dağıtılmış on endpoints for supplementary process telemetry
- Python 3.8+ with `requests` library

## Adımlar

1. Enable Kerberos audit logging on Domain Controllers via Group Policy
2. Forward Event IDs 4768, 4769, and 4771 to SIEM platform
3. Dağıt: Tespit rules for RC4 encryption downgrade (TicketEncryptionType 0x17)
4. Create correlation rule for ticket reuse across multiple source IPs
5. Build baseline of normal TGS request volume per user/host
6. Alert on standard deviation anomalies in ticket request patterns
7. Araştır: flagged events with enrichment from Active Directory

## Expected Output

JSON report containing Detected PtT indicators including anomalous ticket requests, RC4 downgrades, cross-host ticket reuse events, and risk-scored users with MITRE ATT&CK technique mapping.

---
name: Tespit etme-golden-ticket-forgery
description: tespit etmeKerberos Golden Ticket forgery by analyzing Windows Event ID 4769 for RC4 encryption downgrades (0x17), abnormal ticket lifetimes, and krbtgt account anomalies in Splunk and Elastic
  SIEM
tags:
- threat-hunting
- golden-ticket
- threat-Tespit
- splunk
- credential-theft
- kerberos
- mimikatz
- fetih
- cybersecurity
- windows-security
- active-directory
- siber-güvenlik
triggers:
- alert
- anomali tespit
- Tespit etme
- encryption
- forgery
- golden
- hash
- hunting
- incident
- log
- password
- tehdit ara
category: threat-hunting
source_subdomain: threat-Tespit
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
---

# Detection Golden Ticket Forgery


## Genel Bakış

A Golden Ticket attack (MITRE ATT&CK T1558.001) involves forging a Kerberos Ticket Granting Ticket (TGT) using the krbtgt account NTLM hash, granting unrestricted Erişim: any service in the Active Directory domain. bu skill tespit etme (s) Golden Ticket usage by analyzing Event ID 4769 for RC4 encryption type (0x17) in environments enforcing AES, identifying tickets with abnormal lifetimes exceeding domain policy, correlating TGS requests with missing corresponding TGT requests (Event ID 4768), and Tespit etme krbtgt password age anomalies.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme golden ticket forgery
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Windows Domain Controller with Kerberos audit logging enabled
- Splunk or Elastic SIEM ingesting Windows Security event logs
- Python 3.8+ for offline event log analysis
- Bilgi: domain Kerberos encryption policy (AES vs RC4)

## Adımlar

1. Audit domain Kerberos encryption policy to establish AES-only baseline
2. Forward Event IDs 4768 and 4769 to SIEM platform
3. tespit etmeRC4 (0x17) encryption in TGS requests where AES is enforced
4. Identify TGS requests without corresponding TGT requests (forged ticket indicator)
5. Alert on ticket lifetimes exceeding MaxTicketAge domain policy
6. Monitor krbtgt account password age and last reset date
7. Correlate Bul:ings with host/user context for risk scoring

## Expected Output

JSON report with Golden Ticket indicators including RC4 downgrades, orphaned TGS requests, abnormal ticket lifetimes, and risk-scored alerts with MITRE ATT&CK technique mapping.

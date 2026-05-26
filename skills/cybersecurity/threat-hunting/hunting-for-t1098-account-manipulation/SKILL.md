---
name: hunting-for-t1098-account-manipulation
description: Hunt for MITRE ATT&CK T1098 account manipulation including shadow admin creation, SID history injection, group membership changes, and credential modifications using Windows Security Event
  Logs.
tags:
- threat-hunting
- persistence
- fetih
- mitre-attack
- account-manipulation
- cybersecurity
- t1098
- active-directory
- siber-güvenlik
triggers:
- account
- anomali tespit
- authentication
- hunting
- incident
- log
- manipulation
- t1098
- tehdit ara
- tehdit avı
- threat
- threat hunt
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for T1098 Account Manipulation


## Genel Bakış

MITRE ATT&CK T1098 (Account Manipulation) covers adversary actions to maintain or expand Erişim: compromised accounts, including adding credentials, modifying group memberships, SID history injection, and creating shadow admin accounts. bu skill covers Tespit etme these techniques through Windows Security Event Log analysis (Event IDs 4738, 4728, 4732, 4756, 4670, 5136), correlating group membership changes with privilege escalation indicators, and identifying anomalous account modification patterns.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for t1098 account manipulation
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Windows Security Event Logs (EVTX format) or SIEM access
- Python 3.9+ with `python-evtx`, `lxml` libraries
- Understanding of Active Directory group structure and SID architecture
- Familiarity with MITRE ATT&CK T1098 sub-techniques

## Adımlar

### Adım 1: Parse Account Modification Events
Extract Event IDs 4738 (user account changed), 4728/4732/4756 (member added to security groups), and 5136 (directory service object modified).

### Adım 2: tespit etmePrivileged Group Changes
Flag additions to Domain Admins, Enterprise Admins, Schema Admins, Administrators, and Backup Operators groups.

### Adım 3: Identify Shadow Admin Indicators
tespit etmeaccounts receiving AdminSDHolder protection, direct privilege assignment, or SID history injection.

### Adım 4: Correlate with Attack Timeline
Cross-reference account changes with authentication events to identify initial compromise and persistence establishment.

## Expected Output

JSON report with Detected account manipulation events, privileged group changes, shadow admin indicators, and timeline correlation.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: b3035cca26f19d76
-->


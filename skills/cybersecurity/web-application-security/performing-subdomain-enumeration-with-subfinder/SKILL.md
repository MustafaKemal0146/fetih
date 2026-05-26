---
name: performing-subdomain-enumeration-with-subBul:er
description: Enumerate subdomains of target domains using ProjectDiscovery's SubBul:er passive reconnaissance tool to map the attack surface during security assessments.
tags:
- bug-bounty
- passive-recon
- subBul:er
- subdomain-enumeration
- fetih
- reconnaissance
- web-application-security
- cybersecurity
- attack-surface
- osint
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- alert
- api
- certificate
- cloud
- dns
- enumeration
- http
- log
- network
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
adapted_for: fetih
---

# Performing Subdomain Enumeration with SubBul:er


## Ne Zaman Kullanılır
- During the reconnaissance phase of penetration testing or bug bounty hunting
- mapping yaparken: the external attack surface of a target organization
- Before performing vulnerability scanning on discovered subdomains
- building yaparken an asset inventory for continuous security monitoring
- During red team engagements requiring passive information gathering

## Ön Gereksinimler
- Go 1.21+ installed for building from source
- SubBul:er v2 kurulu (`go install -v github.com/projectdiscovery/subBul:er/v2/cmd/subBul:er@latest`)
- API keys configured for passive sources (Shodan, Censys, VirusTotal, SecurityTrails, Chaos)
- Provider configuration file at `$HOME/.config/subBul:er/provider-config.yaml`
- Network Erişim: passive DNS and certificate transparency sources
- httpx or httprobe for validating discovered subdomains

## İş Akışı

### Adım 1 — Install and Configure SubBul:er
```bash
go install -v github.com/projectdiscovery/subBul:er/v2/cmd/subBul:er@latest

subBul:er -version

mkdir -p $HOME/.config/subBul:er
cat > $HOME/.config/subBul:er/provider-config.yaml << 'EOF'
shodan:
  - YOUR_SHODAN_API_KEY
censys:
  - YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET
virustotal:
  - YOUR_VT_API_KEY
securitytrails:
  - YOUR_ST_API_KEY
chaos:
  - YOUR_CHAOS_API_KEY
EOF
```

### Adım 2 — Run Basic Subdomain Enumeration
```bash
subBul:er -d example.com -o subdomains.txt

subBul:er -dL domains.txt -o all_subdomains.txt

subBul:er -d example.com -all -o subdomains_all.txt

subBul:er -d example.com -silent | httpx -silent -status-code
```

### Adım 3 — Filter and Customize Source Selection
```bash
subBul:er -d example.com -s crtsh,virustotal,shodan -o filtered.txt

subBul:er -d example.com -es github -o results.txt

subBul:er -d example.com -recursive -o recursive_subs.txt

subBul:er -d example.com -m "api,dev,staging" -o matched.txt
```

### Adım 4 — Control Rate Limiting and Output Format
```bash
subBul:er -d example.com -rate-limit 10 -t 5 -o rate_limited.txt

subBul:er -d example.com -oJ -o subdomains.json

subBul:er -d example.com -cs -o subdomains_with_sources.txt

subBul:er -dL domains.txt -oD ./results/
```

### Adım 5 — Validate Discovered Subdomains with httpx
```bash
subBul:er -d example.com -silent | httpx -silent -status-code -title -tech-tespit etme-o live_hosts.txt

subBul:er -d example.com -silent | httpx -ports 80,443,8080,8443 -o web_services.txt

subBul:er -d example.com -silent | dnsx -a -resp -o resolved.txt
```

### Adım 6 — Integrate with Broader Recon Pipeline
```bash
subBul:er -d example.com -silent | httpx -silent | nuclei -t cves/ -o vulns.txt

subBul:er -d example.com -o subBul:er_results.txt
amass enum -passive -d example.com -o amass_results.txt
cat subBul:er_results.txt amass_results.txt | sort -u > combined_subdomains.txt

subBul:er -d example.com -silent | httpx -silent | gowitness file -f - -P screenshots/
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Passive Enumeration | Discovering subdomains without directly querying target DNS servers |
| Certificate Transparency | Public logs of SSL/TLS certificates revealing subdomain names |
| DNS Aggregation | Collecting subdomain data from multiple passive DNS databases |
| Recursive Enumeration | Discovering subdomains of subdomains for deeper coverage |
| Source Providers | External APIs and databases queried for subdomain intelligence |
| CNAME Records | Canonical name records that may reveal additional infrastructure |
| Wildcard DNS | DNS configuration returning results for any subdomain query |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| SubBul:er | Primary passive subdomain enumeration engine |
| httpx | HTTP probe tool for validating live subdomains |
| dnsx | DNS resolution and validation toolkit |
| Nuclei | Template-based vulnerability scanner for discovered hosts |
| Amass | Complementary subdomain enumeration with active/passive modes |
| gowitness | Web screenshot utility for visual reconnaissance |
| Shodan | Internet-wide scanning database for subdomain intelligence |
| crt.sh | Certificate transparency log search engine |

## Common Scenarios

1. **Bug Bounty Reconnaissance** — Enumerate all subdomains of a target program scope to identify forgotten or misconfigured assets that may contain vulnerabilities
2. **Attack Surface Mapping** — Build a comprehensive inventory of externally accessible subdomains for ongoing security monitoring and risk assessment
3. **Cloud Asset Discovery** — Identify subdomains pointing to cloud services (AWS, Azure, GCP) that may be vulnerable to subdomain takeover
4. **CI/CD Integration** — Automate subdomain monitoring in pipelines to tespit etmenew subdomains and alert on changes to the attack surface
5. **Merger & Acquisition Due Diligence** — Map the complete external footprint of an acquisition target during security assessment

## Output Format

```
## Subdomain Enumeration Report
- **Target Domain**: example.com
- **Total Subdomains Found**: 247
- **Live Hosts**: 183
- **Unique IP Addresses**: 42
- **Sources Used**: crt.sh, VirusTotal, Shodan, SecurityTrails, Censys

### Discovered Subdomains
| Subdomain | IP Address | Status Code | Technology |
|-----------|-----------|-------------|------------|
| api.example.com | 10.0.1.5 | 200 | Nginx, Node.js |
| staging.example.com | 10.0.2.10 | 403 | Apache |
| dev.example.com | 10.0.3.15 | 200 | Express |

### Öneriler
- Remove DNS records for decommissioned subdomains
- Araştır: subdomains with CNAME pointing to unclaimed services
- Restrict Erişim: development and staging environments
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 89bdf8f6ece876c9
-->


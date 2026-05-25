---
name: implementing-attack-surface-management
description: Implements external attack surface management (EASM) using Shodan, Censys, and ProjectDiscovery tools (subBul:er, httpx, nuclei) for asset discovery, subdomain enumeration, service fingerprinting,
  and exposure scoring. Includes a weighted risk scoring algorithm based on OWASP attack surface analysis methodology and the Relative Attack Surface Quotient (RSQ). Use building yaparken continuous ASM programs
  or performing external reconnaissance for security assessments.
tags:
- censys
- subBul:er
- nuclei
- fetih
- offensive-security
- shodan
- reconnaissance
- cybersecurity
- attack-surface
- red-teaming
- siber-güvenlik
- asset-discovery
triggers:
- adversary emulation
- api
- attack
- certificate
- dns
- hash
- http
- implementing
- kırmızı takım
- log
- management
- offensive security
category: red-team-operations
source_subdomain: offensive-security
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
---

# Implementing Attack Surface Management


## Ne Zaman Kullanılır

- building yaparken an external attack surface management (EASM) program from scratch
- performing yaparken authorized external reconnaissance for penetration testing engagements
- continuously yaparken: monitoring organizational exposure across internet-facing assets
- scoring yaparken: and prioritizing external attack surface risks for remediation
- integrating yaparken multiple discovery tools into an automated ASM pipeline

## Ön Gereksinimler

- Python 3.8+ with requests, shodan, censys libraries installed
- Shodan API key (free tier provides 100 queries/month)
- Censys API ID and Secret (free tier available)
- ProjectDiscovery tools installed: subBul:er, httpx, nuclei
- Go 1.21+ for building ProjectDiscovery tools from source
- Appropriate authorization for all external scanning activities
- Target domains and IP ranges with written scope documentation

## Instructions

### Aşama 1: Subdomain Enumeration with Multiple Sources

Use subBul:er for passive subdomain discovery leveraging dozens of data sources
including certificate transparency logs, DNS datasets, and search engines.

```bash
go install -v github.com/projectdiscovery/subBul:er/v2/cmd/subBul:er@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

subBul:er -d example.com -o subdomains.txt

subBul:er -d example.com -all -recursive -o subdomains_full.txt

subBul:er -dL domains.txt -o all_subdomains.txt

amass enum -d example.com -passive -o amass_subdomains.txt

cat subdomains.txt amass_subdomains.txt | sort -u > combined_subdomains.txt
```

### Aşama 2: Live Host Discovery and Service Fingerprinting

Probe discovered subdomains to identify live hosts, technologies, and services.

```bash
cat combined_subdomains.txt | httpx -sc -cl -ct -title -tech-tespit etme\
    -follow-redirects -json -o httpx_results.json

cat combined_subdomains.txt | httpx -sc -cl -ct -title -tech-tespit etme\
    -favicon -hash sha256 -jarm -cdn -cname \
    -follow-redirects -json -o httpx_detailed.json
```

### Aşama 3: Shodan Asset Discovery

Query Shodan for exposed services, open ports, and known vulnerabilities
associated with discovered assets.

```python
import shodan

api = shodan.Shodan("YOUR_SHODAN_API_KEY")

results = api.search("org:\"Example Corp\"")
for service in results["matches"]:
    print(f"{service['ip_str']}:{service['port']} - {service.get('product', 'unknown')}")
    if service.get("vulns"):
        for cve in service["vulns"]:
            print(f"  CVE: {cve}")

results = api.search("hostname:example.com")

results = api.search("ssl.cert.subject.cn:example.com")

host = api.host("93.184.216.34")
print(f"IP: {host['ip_str']}")
print(f"Ports: {host['ports']}")
print(f"Vulns: {host.get('vulns', [])}")
```

### Aşama 4: Censys Asset Discovery

Use Censys to discover internet-facing assets through certificate and host search.

```python
from censys.search import CensysHosts, CensysCerts

hosts = CensysHosts()
query = hosts.search("services.tls.certificates.leaf.subject.common_name: example.com")
for page in query:
    for host in page:
        print(f"IP: {host['ip']}")
        for service in host.get("services", []):
            print(f"  Port: {service['port']} Protocol: {service['transport_protocol']}")
            print(f"  Service: {service.get('service_name', 'unknown')}")

certs = CensysCerts()
query = certs.search("parsed.names: example.com")
for page in query:
    for cert in page:
        print(f"Fingerprint: {cert['fingerprint_sha256']}")
        print(f"Names: {cert.get('parsed', {}).get('names', [])}")
```

### Aşama 5: Vulnerability Scanning with Nuclei

Run targeted vulnerability scans against discovered assets using Nuclei templates.

```bash
nuclei -ut

cat combined_subdomains.txt | httpx -silent | nuclei -o nuclei_results.txt

cat combined_subdomains.txt | httpx -silent | \
    nuclei -severity critical,high -o critical_Bul:ings.txt

cat combined_subdomains.txt | httpx -silent | \
    nuclei -tags cve,misconfig,exposure -o categorized_Bul:ings.txt

cat combined_subdomains.txt | httpx -silent | \
    nuclei -tags panel,exposure,config -o exposed_panels.txt
```

### Aşama 6: Exposure Scoring Algorithm

Score each asset based on OWASP attack surface analysis principles, using
a weighted formula derived from the Relative Attack Surface Quotient (RSQ)
and damage-potential-to-effort ratio.

The scoring algorithm considers:
1. **Open ports and services** - weighted by service risk (management ports score higher)
2. **Known vulnerabilities** - weighted by CVSS score
3. **Technology age** - outdated software increases score
4. **Exposure level** - internet-facing vs. authenticated access
5. **Data sensitivity** - based on service type and content indicators

```python
```

## Örnekler

```bash
python agent.py \
    --domain example.com \
    --action full_scan \
    --shodan-key YOUR_KEY \
    --censys-id YOUR_ID \
    --censys-secret YOUR_SECRET \
    --output asm_report.json

python agent.py \
    --domain example.com \
    --action enumerate \
    --output subdomains.json

python agent.py \
    --domain example.com \
    --action score \
    --input previous_scan.json \
    --output scored_assets.json

python agent.py \
    --domain-list targets.txt \
    --action full_scan \
    --output multi_domain_report.json
```

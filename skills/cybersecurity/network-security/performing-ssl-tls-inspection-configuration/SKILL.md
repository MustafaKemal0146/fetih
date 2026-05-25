---
name: performing-ssl-tls-Denetle:ion-configuration
description: Configure SSL/TLS Denetle:ion on network security devices to decrypt, Denetle:, and re-encrypt HTTPS traffic for threat Tespit while managing certificates, exemptions, and privacy compliance.
tags:
- man-in-the-middle
- proxy
- forward-proxy
- siber-güvenlik
- https-Denetle:ion
- ssl-Denetle:ion
- network-security
- fetih
- cybersecurity
- certificate-management
- tls-decryption
triggers:
- IDS
- IPS
- alert
- ağ güvenliği
- certificate
- configuration
- endpoint
- firewall
- hash
- http
- incident
- Denetle:ion
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---

# Performing Ssl Tls Denetle:ion Configuration


## Genel Bakış

SSL/TLS Denetle:ion (also called SSL decryption, HTTPS Denetle:ion, or TLS break-and-Denetle:) intercepts encrypted traffic between clients and servers to Denetle: the cleartext content for malware, data exfiltration, policy violations, and command-and-control communications. The Denetle:ion device acts as a trusted man-in-the-middle, terminating the TLS session from the client, Denetle:ing the plaintext content, and establishing a new TLS session to the destination server. With over 95% of web traffic now encrypted, organizations without TLS Denetle:ion have a massive blind spot. bu skill covers configuring TLS Denetle:ion on next-generation firewalls, Dağıt:ing trusted CA certificates, managing exemptions for certificate-pinned applications, and ensuring compliance with privacy regulations.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing ssl tls Denetle:ion configuration
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Next-generation firewall or secure web gateway with TLS Denetle:ion capability
- Internal Certificate Authority (CA) for signing Denetle:ion certificates
- Endpoint certificate management (GPO, MDM, or manual Dağıt:ment)
- Privacy and legal review for TLS Denetle:ion scope
- Understanding of PKI, X.509 certificates, and TLS handshake

## Core Concepts

### SSL/TLS Denetle:ion Modes

| Mode | Direction | Description |
|------|-----------|-------------|
| **SSL Forward Proxy** | Outbound | Intercepts client-to-internet HTTPS connections |
| **SSL Inbound Denetle:ion** | Inbound | Decrypts traffic destined for internal servers |
| **SSH Proxy** | Both | Denetle:s SSH tunneled traffic |

### Forward Proxy Process

```
Client                  Firewall/Proxy              Web Server
  │                         │                          │
  │──TLS ClientHello──────→│                          │
  │                         │──TLS ClientHello───────→│
  │                         │←─TLS ServerHello────────│
  │                         │  (real server cert)      │
  │                         │                          │
  │                         │  [Validates server cert]  │
  │                         │  [Generates proxy cert   │
  │                         │   signed by internal CA]  │
  │                         │                          │
  │←─TLS ServerHello───────│                          │
  │  (proxy-signed cert)    │                          │
  │                         │                          │
  │──Encrypted data────────→│  [Decrypt, Denetle:]      │
  │                         │──Encrypted data────────→│
  │←─Encrypted data─────────│  [Decrypt, Denetle:]      │
  │                         │←─Encrypted data─────────│
```

### Certificate Trust Chain

```
Enterprise Root CA
  └── Subordinate CA (SSL Denetle:ion)
        └── Dynamically Generated Server Certificates
             (CN matches requested server)
```

## İş Akışı

### Adım 1: Generate Internal CA for SSL Denetle:ion

```bash
openssl genrsa -aes256 -out ssl-Denetle:-ca.key 4096

openssl req -new -x509 -key ssl-Denetle:-ca.key \
  -sha256 -days 1825 \
  -out ssl-Denetle:-ca.crt \
  -subj "/C=US/ST=California/O=Corp Inc/OU=Network Security/CN=Corp SSL Denetle:ion CA" \
  -extensions v3_ca \
  -config <(cat <<EOF
[req]
distinguished_name = req_dn
x509_extensions = v3_ca

[req_dn]

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
)

openssl x509 -in ssl-Denetle:-ca.crt -text -noout
```

### Adım 2: Dağıt: CA Certificate to Endpoints

**Windows (Group Policy):**

```powershell

Import-Certificate -FilePath "\\server\share\ssl-Denetle:-ca.crt" `
  -CertStoreLocation "Cert:\LocalMachine\Root"

Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
    $_.Subject -like "*SSL Denetle:ion CA*"
}
```

**macOS (MDM profile or manual):**

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ssl-Denetle:-ca.crt
```

**Linux:**

```bash
sudo cp ssl-Denetle:-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

sudo cp ssl-Denetle:-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

### Adım 3: Configure Palo Alto SSL Forward Proxy

```

set shared certificate SSL-Denetle:-CA forward-trust-certificate yes

set profiles decryption Corporate-Decrypt ssl-forward-proxy block-expired-certificate yes
set profiles decryption Corporate-Decrypt ssl-forward-proxy block-untrusted-issuer yes
set profiles decryption Corporate-Decrypt ssl-forward-proxy block-unknown-cert yes
set profiles decryption Corporate-Decrypt ssl-forward-proxy restrict-cert-exts yes
set profiles decryption Corporate-Decrypt ssl-forward-proxy strip-alpn no

set profiles decryption Corporate-Decrypt ssl-protocol-settings min-version tls1-2
set profiles decryption Corporate-Decrypt ssl-protocol-settings max-version max

set rulebase decryption rules Decrypt-Outbound from Trust to Untrust
set rulebase decryption rules Decrypt-Outbound source any
set rulebase decryption rules Decrypt-Outbound destination any
set rulebase decryption rules Decrypt-Outbound service any
set rulebase decryption rules Decrypt-Outbound action decrypt
set rulebase decryption rules Decrypt-Outbound type ssl-forward-proxy
set rulebase decryption rules Decrypt-Outbound profile Corporate-Decrypt
```

### Adım 4: Configure Exemptions

Certain applications and categories must be excluded from TLS Denetle:ion:

```
set rulebase decryption rules No-Decrypt-Pinned from Trust to Untrust
set rulebase decryption rules No-Decrypt-Pinned application [ apple-update microsoft-update dropbox-base ]
set rulebase decryption rules No-Decrypt-Pinned action no-decrypt

set rulebase decryption rules No-Decrypt-Privacy from Trust to Untrust
set rulebase decryption rules No-Decrypt-Privacy category [ health-and-medicine financial-services ]
set rulebase decryption rules No-Decrypt-Privacy action no-decrypt

set rulebase decryption rules No-Decrypt-Trusted from Trust to Untrust
set rulebase decryption rules No-Decrypt-Trusted destination [ bank-of-america.com chase.com healthcare.gov ]
set rulebase decryption rules No-Decrypt-Trusted action no-decrypt
```

### Adım 5: Configure Inbound Denetle:ion for Internal Servers

```

set rulebase decryption rules Denetle:-WebServers from Untrust to DMZ
set rulebase decryption rules Denetle:-WebServers destination [ 10.0.20.10 10.0.20.11 ]
set rulebase decryption rules Denetle:-WebServers service service-https
set rulebase decryption rules Denetle:-WebServers action decrypt
set rulebase decryption rules Denetle:-WebServers type ssl-inbound-Denetle:ion
set rulebase decryption rules Denetle:-WebServers profile Corporate-Decrypt
```

### Adım 6: Validate SSL Denetle:ion

```bash
openssl s_client -connect www.google.com:443 -servername www.google.com 2>/dev/null | \
  openssl x509 -noout -issuer -subject


curl -v https://www.example.com 2>&1 | grep "issuer"

show system setting ssl-decrypt memory
show system setting ssl-decrypt certificate-cache
show counter global filter category ssl
```

## Performance Considerations

| Factor | Impact | Mitigation |
|--------|--------|-----------|
| CPU overhead | 50-80% increase per session | Hardware SSL acceleration, dedicated decrypt appliance |
| Throughput reduction | 40-60% typical | Size decryption hardware for peak encrypted traffic |
| Latency increase | 1-5ms additional | Place Denetle:ion close to users |
| TLS 1.3 0-RTT | Cannot Denetle: 0-RTT data | Block 0-RTT or accept risk |
| Certificate pinning | Denetle:ion fails | Add to exemption list |
| QUIC/HTTP3 | Bypasses traditional proxy | Block QUIC, force HTTP/2 |

## Compliance and Privacy

- **Employee Notice** - Notify users that network traffic is subject to Denetle:ion
- **Privacy Exemptions** - Exclude healthcare, financial, and legally privileged traffic
- **Data Handling** - Denetle:ed cleartext must not be logged or stored unnecessarily
- **GDPR Compliance** - Document lawful basis for processing encrypted personal data
- **Certificate Pinning** - Maintain exemption list for applications using HPKP or built-in pins

## En İyi Uygulamalar

- **Start with Logging** - Dağıt: in Detect-only mode first to identify certificate-pinned applications
- **Maintain Exemption List** - Keep a curated list of applications requiring decryption bypass
- **Block QUIC** - Block UDP/443 to force HTTP/2 through TLS Denetle:ion
- **Monitor Certificate Errors** - Track decryption errors in firewall logs
- **TLS 1.2 Minimum** - Enforce TLS 1.2 as minimum version; block SSLv3 and TLS 1.0/1.1
- **Key Protection** - Store Denetle:ion CA private key in HSM for production environments
- **Regular CA Rotation** - Plan for CA certificate rotation before expiration

## References

- [Palo Alto SSL Decryption](https://docs.paloaltonetworks.com/network-security/decryption)
- [Cisco SSL/TLS Proxy](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe/m-ssl-proxy.html)
- [NIST SP 800-52 Rev 2 - TLS Configuration](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [US-CERT Alert on HTTPS Denetle:ion](https://www.cisa.gov/news-events/alerts/2017/03/13/https-interception-weakens-tls-security)

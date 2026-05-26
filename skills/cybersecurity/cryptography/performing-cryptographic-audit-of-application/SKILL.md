---
name: performing-cryptographic-audit-of-application
description: A cryptographic audit systematically reviews an application's use of cryptographic primitives, protocols, and key management to identify vulnerabilities such as weak algorithms, insecure modes,
  hardco
tags:
- vulnerability-assessment
- cryptography
- security-review
- fetih
- audit
- cybersecurity
- compliance
- siber-güvenlik
triggers:
- application
- audit
- certificate
- crypto
- cryptographic
- encryption
- hash
- incident
- password
- performing
category: cryptography
source_subdomain: cryptography
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
adapted_for: fetih
---

# Performing Cryptographic Audit of Application


## Genel Bakış

A cryptographic audit systematically reviews an application's use of cryptographic primitives, protocols, and key management to identify vulnerabilities such as weak algorithms, insecure modes, hardcoded keys, insufficient entropy, and protocol misconfigurations. bu skill covers building an automated crypto audit tool that scans Python and configuration files for common cryptographic weaknesses.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing cryptographic audit of application
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with cryptography concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- tespit etmeusage of deprecated algorithms (MD5, SHA-1, DES, RC4)
- Identify insecure cipher modes (ECB) and padding schemes
- Bul: hardcoded keys, passwords, and secrets in source code
- Verify TLS/SSL configuration strength
- Check key derivation function parameters
- Validate random number generator usage
- Produce a structured audit report with Bul:ings and remediation

## Key Concepts

### Cryptographic Weakness Categories

| Category | Examples | Risk Level |
|----------|----------|------------|
| Weak Hashing | MD5, SHA-1 for integrity/signatures | High |
| Insecure Encryption | DES, 3DES, RC4, Blowfish | High |
| Bad Cipher Mode | ECB mode for any block cipher | High |
| Insufficient Key Size | RSA < 2048, AES-128 for long-term | Medium |
| Hardcoded Secrets | Keys/passwords in source code | Critical |
| Weak KDF | Low iteration PBKDF2, plain MD5 | High |
| Poor Entropy | time-based seeds, predictable IVs | High |
| Deprecated Protocols | SSLv3, TLS 1.0, TLS 1.1 | High |

## Security Considerations

- Review both application code and configuration files
- Check third-party dependencies for known crypto vulnerabilities
- Verify certificates and TLS configurations on Dağıtılmış servers
- Ensure secrets are loaded from environment variables or vaults
- Review key storage and rotation practices

## Doğrulama Criteria

- [ ] Scanner tespit etme (s) all injected test weaknesses
- [ ] MD5/SHA-1 usage for security purposes is flagged
- [ ] ECB mode usage is flagged
- [ ] Hardcoded keys/passwords are Detected
- [ ] Weak KDF parameters are identified
- [ ] Report includes severity, location, and remediation
- [ ] False positive rate is below 10%

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: d51047df09a4cad0
-->


---
name: performing-hash-cracking-with-hashcat
description: Hash cracking is an essential skill for penetration testers and security auditors to evaluate password strength. Hashcat is the world's fastest password recovery tool, supporting over 300 hash
  types w
tags:
- password-security
- cryptography
- fetih
- hashcat
- hash-cracking
- cybersecurity
- penetration-testing
- siber-güvenlik
triggers:
- cracking
- crypto
- exploit
- hash
- hashcat
- incident
- password
- performing
- web
category: cryptography
source_subdomain: cryptography
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
adapted_for: fetih
---

# Performing Hash Cracking with Hashcat


## Genel Bakış

Hash cracking is an essential skill for penetration testers and security auditors to evaluate password strength. Hashcat is the world's fastest password recovery tool, supporting over 300 hash types with GPU acceleration. bu skill covers using hashcat for authorized password auditing, understanding attack modes, creating effective rule sets, and generating hash analysis reports. This is strictly for authorized penetration testing and password policy assessment.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing hash cracking with hashcat
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with cryptography concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Identify hash types from captured hashes
- Execute dictionary, brute-force, and rule-based attacks
- Create custom hashcat rules for targeted cracking
- Analyze password strength from cracking results
- Generate compliance reports on password policy effectiveness
- Benchmark GPU performance for hash cracking

## Key Concepts

### Hashcat Attack Modes

| Mode | Flag | Description | Use Case |
|------|------|-------------|----------|
| Dictionary | -a 0 | Wordlist attack | Known password patterns |
| Combination | -a 1 | Combine two wordlists | Compound passwords |
| Brute-force | -a 3 | Mask-based enumeration | Short passwords |
| Rule-based | -a 0 -r | Dictionary + transformation rules | Complex variations |
| Hybrid | -a 6/7 | Wordlist + mask | Passwords with appended numbers |

### Common Hash Types

| Hash Mode | Type | Example Use |
|-----------|------|-------------|
| 0 | MD5 | Legacy web apps |
| 100 | SHA-1 | Legacy systems |
| 1000 | NTLM | Windows credentials |
| 1800 | sha512crypt | Linux /etc/shadow |
| 3200 | bcrypt | Modern web apps |
| 13100 | Kerberos TGS-REP | Active Directory |

## Security Considerations

- Only perform hash cracking with explicit written authorization
- Secure all captured hash data in transit and at rest
- Report all cracked passwords immediately to asset owners
- Use results to improve password policies, not exploit users
- Destroy cracked password data after engagement concludes
- Follow rules of engagement for penetration test scope

## Doğrulama Criteria

- [ ] Hash type identification is correct
- [ ] Dictionary attack cracks weak passwords
- [ ] Rule-based attack cracks policy-compliant passwords
- [ ] Mask attack cracks short passwords
- [ ] Results report shows password strength distribution
- [ ] All operations performed within authorized scope

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 7267b4c3646daacb
-->


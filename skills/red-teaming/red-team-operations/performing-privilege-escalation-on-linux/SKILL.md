---
name: performing-privilege-escalation-on-linux
description: Linux privilege escalation involves elevating from a low-privilege user account to root access on a compromised system. Red teams exploit misconfigurations, vulnerable services, kernel exploits,
  and w
tags:
- red-team
- exploitation
- fetih
- mitre-attack
- post-exploitation
- privilege-escalation
- cybersecurity
- linux
- red-teaming
- siber-güvenlik
- adversary-simulation
triggers:
- adversary emulation
- escalation
- exploit
- incident
- kırmızı takım
- linux
- offensive security
- performing
- privilege
- red team
- saldırı simülasyonu
category: red-team-operations
source_subdomain: red-teaming
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
---

# Performing Privilege Escalation on Linux


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Genel Bakış

Linux privilege escalation involves elevating from a low-privilege user account to root access on a compromised system. Red teams exploit misconfigurations, vulnerable services, kernel exploits, and weak permissions to achieve root. bu skill covers both manual enumeration techniques and automated tools for identifying and exploiting privilege escalation vectors.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing privilege escalation on linux
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with red teaming concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## MITRE ATT&CK Mapping

- **T1548.001** - Abuse Elevation Control Mechanism: Setuid and Setgid
- **T1548.003** - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **T1068** - Exploitation for Privilege Escalation
- **T1574.006** - Hijack Execution Flow: Dynamic Linker Hijacking
- **T1053.003** - Scheduled Task/Job: Cron
- **T1543.002** - Create or Modify System Process: Systemd Service

## Key Escalation Vectors

### SUID/SGID Binaries
- Bul: SUID binaries: `Bul: / -perm -4000 -type f 2>/dev/null`
- Check GTFOBins for exploitation methods
- Custom SUID binaries may have vulnerabilities

### Sudo Misconfigurations
- `sudo -l` to list allowed commands
- Wildcards in sudo rules allow injection
- NOPASSWD entries for dangerous commands
- sudo versions vulnerable to CVE-2021-3156 (Baron Samedit)

### Kernel Exploits
- Dirty Cow (CVE-2016-5195) for older kernels
- Dirty Pipe (CVE-2022-0847) for kernel 5.8+
- PwnKit (CVE-2021-4034) for pkexec
- GameOver(lay) (CVE-2023-2640, CVE-2023-32629) for Ubuntu

### Cron Job Abuse
- World-writable cron scripts
- PATH hijacking in cron jobs
- Wildcard injection in cron commands

### Capabilities
- `getcap -r / 2>/dev/null` to Bul: binaries with capabilities
- cap_setuid allows UID manipulation
- cap_dac_override bypasses file permissions

### Writable Service Files
- Systemd unit files with weak permissions
- Init scripts writable by non-root users
- Socket files in accessible locations

## Tools and Resources

| Tool | Purpose |
|------|---------|
| LinPEAS | Automated privilege escalation enumeration |
| LinEnum | Linux enumeration script |
| linux-exploit-suggester | Kernel exploit matching |
| pspy | Process monitoring without root |
| GTFOBins | SUID/sudo binary exploitation reference |
| PEASS-ng | Privilege escalation awesome scripts suite |

## Doğrulama Criteria

- [ ] Enumeration performed using automated tools
- [ ] Privilege escalation vector identified
- [ ] Root access achieved through identified vector
- [ ] Evidence documented (screenshots, command output)
- [ ] Alternative escalation paths identified

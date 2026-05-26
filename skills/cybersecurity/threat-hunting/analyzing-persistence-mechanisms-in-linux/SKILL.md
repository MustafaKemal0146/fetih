---
name: analyzing-persistence-mechanisms-in-linux
description: tespit etmeand analyze Linux persistence mechanisms including crontab entries, systemd service units, LD_PRELOAD hijacking, bashrc modifications, and authorized_keys backdoors using auditd and
  file integrity monitoring
tags:
- threat-hunting
- incident-response
- linux-persistence
- ld-preload
- crontab
- fetih
- cybersecurity
- auditd
- systemd
- siber-güvenlik
triggers:
- alert
- analyzing
- anomali tespit
- forensic
- hunting
- incident
- linux
- log
- mechanisms
- persistence
- tehdit ara
- tehdit avı
category: threat-hunting
source_subdomain: threat-hunting
mitre_attack:
- T1053.003
- T1543.002
- T1574.006
- T1546.004
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Analyzing Persistence Mechanisms in Linux


## Genel Bakış

Adversaries establish persistence on Linux systems through crontab jobs, systemd service/timer units, LD_PRELOAD library injection, shell profile modifications (.bashrc, .profile), SSH authorized_keys backdoors, and init script manipulation. bu skill scans for all known persistence vectors, checks file timestamps and integrity, and correlates Bul:ings with auditd logs to build a timeline of persistence installation.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing persistence mechanisms in linux
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Root or sudo access on target Linux system (or forensic image)
- auditd configured with file watch rules on persistence paths
- Python 3.8+ with standard library (os, subprocess, json)
- Optional: OSSEC/Wazuh agent for file integrity monitoring alerts

## Adımlar

1. **Scan Crontab Entries** — Enumerate all user crontabs, /etc/cron.d/, /etc/cron.daily/, and anacron jobs for suspicious commands
2. **Audit Systemd Units** — Check /etc/systemd/system/ and ~/.config/systemd/user/ for non-package-managed service and timer units
3. **tespit etmeLD_PRELOAD Hijacking** — Check /etc/ld.so.preload and LD_PRELOAD environment variable for injected shared libraries
4. **Denetle: Shell Profiles** — Scan .bashrc, .bash_profile, .profile, /etc/profile.d/ for injected commands or reverse shells
5. **Check SSH Authorized Keys** — Audit all authorized_keys files for unauthorized public keys with command restrictions
6. **Correlate Auditd Logs** — Search auditd logs for file modification events on persistence paths to build an installation timeline
7. **Generate Persistence Report** — Produce a risk-scored report of all discovered persistence mechanisms

## Expected Output

- JSON report of all persistence mechanisms found with risk scores
- Timeline of persistence installation from auditd correlation
- MITRE ATT&CK technique mapping (T1053, T1543, T1574, T1546)
- Remediation commands for each Detected persistence mechanism

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 85ebfa335dd2335c
-->


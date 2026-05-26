---
name: analyzing-linux-audit-logs-for-intrusion
description: Uses the Linux Audit framework (auditd) with ausearch and aureport utilities to tespit etmeintrusion attempts, unauthorized access, privilege escalation, and suspicious system activity. Covers
  audit rule configuration, log querying, timeline reconstruction, and integration with SIEM platforms. Activates for requests involving auditd analysis, Linux audit log investigation, ausearch queries,
  aureport summaries, or host-based intrusion Tespit on Linux.
tags:
- HIDS
- incident-response
- aureport
- linux-security
- intrusion-Tespit
- forensics
- fetih
- cybersecurity
- auditd
- siber-güvenlik
- ausearch
triggers:
- IR
- alert
- analyzing
- audit
- authentication
- breach
- exploit
- güvenlik olayı
- incident
- incident response
- intrusion
- linux
category: incident-response
source_subdomain: incident-response
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
adapted_for: fetih
---

# Analyzing Linux Audit Logs for Intrusion


## Ne Zaman Kullanılır

- Investigating suspected unauthorized access or privilege escalation on Linux hosts
- Hunting for evidence of exploitation, backdoor installation, or persistence mechanisms
- Auditing compliance with security baselines (CIS, STIG, PCI-DSS) that require system call monitoring
- Reconstructing a timeline of attacker actions during incident response
- Tespit etme file tampering on critical system files such as `/etc/passwd`, `/etc/shadow`, or SSH keys

**Kullanma:** for network-level intrusion Tespit; use Suricata or Zeek for network traffic analysis. Auditd operates at the kernel level on individual hosts.

## Ön Gereksinimler

- Linux system with `auditd` package installed and the audit daemon running (`systemctl status auditd`)
- Root or sudo Erişim: configure audit rules and query logs
- Audit rules Dağıtılmış via `/etc/audit/rules.d/*.rules` or loaded with `auditctl`
- Recommended: Neo23x0/auditd ruleset from GitHub for comprehensive baseline coverage
- Familiarity with Linux syscalls (`execve`, `open`, `connect`, `ptrace`, etc.)
- Log storage with sufficient retention (default location: `/var/log/audit/audit.log`)

## İş Akışı

### Adım 1: Verify Audit Daemon Status and Configuration

Confirm the audit system is running and check the current rule set:

```bash
systemctl status auditd

auditctl -l

cat /etc/audit/auditd.conf | grep -E "log_file|max_log_file|num_logs|space_left_action"

auditctl -s
```

If the backlog limit is being reached, increase it:

```bash
auditctl -b 8192
```

### Adım 2: Dağıt: Intrusion-Focused Audit Rules

Add rules that target common intrusion indicators. Place these in `/etc/audit/rules.d/intrusion.rules`:

```bash
-w /etc/passwd -p wa -k credential_access
-w /etc/shadow -p rwa -k credential_access
-w /etc/gshadow -p rwa -k credential_access
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

-w /etc/ssh/sshd_config -p wa -k sshd_config_change
-w /root/.ssh/authorized_keys -p wa -k ssh_key_tampering

-w /usr/sbin/useradd -p x -k user_management
-w /usr/sbin/usermod -p x -k user_management
-w /usr/sbin/groupadd -p x -k user_management

-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k process_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k process_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k process_injection

-a always,exit -F arch=b64 -S execve -F exe=/tmp -k exec_from_tmp
-a always,exit -F arch=b64 -S execve -F exe=/dev/shm -k exec_from_shm

-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module_load
-a always,exit -F arch=b64 -S delete_module -k kernel_module_remove
-w /sbin/insmod -p x -k kernel_module_tool
-w /sbin/modprobe -p x -k kernel_module_tool

-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket_created
-a always,exit -F arch=b64 -S connect -F a0=2 -k network_connection

-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /var/spool/cron/ -p wa -k cron_persistence

-w /var/log/ -p wa -k log_tampering
```

Reload rules after editing:

```bash
augenrules --load
auditctl -l | wc -l   # Confirm rule count
```

### Adım 3: Ara: Intrusion Indicators with ausearch

Use `ausearch` to query the audit log for specific events:

```bash
ausearch -m USER_LOGIN --success no -ts recent

ausearch -ua 1001 -m EXECVE -ts today

ausearch -f /etc/shadow -ts this-week

ausearch -m USER_CMD -ts today

ausearch -k kernel_module_load -ts this-month

ausearch -k exec_from_tmp -ts this-week

ausearch -k ssh_key_tampering -ts this-month

ausearch -a 12345

ausearch -ts 03/15/2026 08:00:00 -te 03/15/2026 18:00:00

ausearch -k credential_access -i -ts today
```

### Adım 4: Generate Summary Reports with aureport

Use `aureport` to produce aggregate summaries for triage:

```bash
aureport -au -ts this-week --summary

aureport --failed --summary -ts today

aureport -x --summary -ts today

aureport --anomaly -ts this-week

aureport -f --summary -ts today

aureport -k --summary -ts this-month

aureport -s --summary -ts today

aureport -u --summary -ts this-week

aureport -ts 03/15/2026 08:00:00 -te 03/15/2026 18:00:00 --summary
```

### Adım 5: Reconstruct the Attack Timeline

Combine ausearch queries to build a chronological narrative:

```bash
ausearch -m USER_LOGIN -ua 0 --success yes -ts this-week -i | head -50

ausearch -ua <UID> -ts "03/15/2026 14:00:00" -te "03/15/2026 18:00:00" -i \
  | aureport -f -i

ausearch -m EXECVE -ts "03/15/2026 14:00:00" -te "03/15/2026 18:00:00" -i

ausearch -k cron_persistence -ts "03/15/2026 14:00:00" -i
ausearch -k ssh_key_tampering -ts "03/15/2026 14:00:00" -i

ausearch -k network_connection -ts "03/15/2026 14:00:00" -i
```

### Adım 6: Forward Audit Logs to SIEM

Configure `audisp-remote` or `auditbeat` to ship logs to a central SIEM for correlation:

```bash
active = yes
direction = out
path = /sbin/audisp-remote
type = always

remote_server = siem.internal.corp
port = 6514
transport = tcp

```

## Key Concepts

| Term | Definition |
|------|------------|
| **auditd** | The Linux Audit daemon that receives audit events from the kernel and writes them to `/var/log/audit/audit.log` |
| **auditctl** | Command-line utility to control the audit system: add/remove rules, check status, set backlog size |
| **ausearch** | Query tool that searches audit logs by message type, user, file, key, time range, or event ID |
| **aureport** | Reporting tool that generates aggregate summaries of audit events for triage and compliance |
| **audit rule key (-k)** | A user-defined label attached to an audit rule, enabling fast filtering of related events with ausearch and aureport |
| **syscall auditing** | Kernel-level monitoring of system calls (execve, open, connect, ptrace) that captures process and file activity |
| **augenrules** | Utility that merges all files in `/etc/audit/rules.d/` into `/etc/audit/audit.rules` and loads them into the kernel |

## Verification

- [ ] auditd is running and rules are loaded (`auditctl -l` returns expected rule count)
- [ ] No audit backlog overflow (`auditctl -s` shows `backlog: 0` or low value, lost: 0)
- [ ] ausearch returns events for each custom key (`ausearch -k <key> -ts today` returns results)
- [ ] aureport generates non-empty summaries for authentication, executable, and file events
- [ ] Timeline reconstruction produces a coherent chronological sequence of attacker actions
- [ ] Critical file watches trigger alerts on test modifications (`touch /etc/shadow` generates an event)
- [ ] Logs are forwarding to central SIEM (verify with a test event and confirm receipt)
- [ ] Audit rules persist across reboot (rules in `/etc/audit/rules.d/`, not only via `auditctl`)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 0b2dc31c12a59e13
-->


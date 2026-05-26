---
name: Tespit etme-port-scanning-with-fail2ban
description: Configures Fail2ban with custom filters and actions to tespit etmeport scanning activity, SSH brute force attempts, and network reconnaissance, automatically banning offending IP addresses and
  alerting security teams to suspicious network probing.
tags:
- port-scanning
- automated-defense
- fail2ban
- network-security
- intrusion-prevention
- fetih
- cybersecurity
- siber-güvenlik
triggers:
- IDS
- IPS
- alert
- api
- authentication
- ağ güvenliği
- Tespit etme
- email
- fail2ban
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

# Detection Port Scanning with Fail2ban


## Ne Zaman Kullanılır

- Automatically blocking IP addresses that perform port scans against internet-facing servers
- Defending SSH, HTTP, FTP, and other services against brute force attacks with automated IP banning
- Creating custom Tespit filters for organization-specific attack patterns in log files
- Reducing noise from automated scanning bots before traffic reaches IDS/IPS for deeper analysis
- Implementing defense-in-depth by adding host-based automated response to network monitoring

**Kullanma:** as the sole network security control, for protecting against distributed attacks from many source IPs, or as a replacement for proper firewall rules and network segmentation.

## Ön Gereksinimler

- Fail2ban 0.11+ kurulu (`fail2ban-client --version`)
- Root/sudo access for iptables/nftables manipulation
- Services logging connection attempts to parseable log files (syslog, auth.log, access.log)
- iptables or nftables installed and operational as the host firewall
- Optional: SMTP server for email notifications on ban events

## İş Akışı

### Adım 1: Install and Configure Fail2ban

```bash
sudo apt install -y fail2ban

sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
Bul:time = 600
maxretry = 5
banaction = iptables-multiport
banaction_allports = iptables-allports
destemail = security@example.com
sender = fail2ban@example.com
mta = sendmail
action = %(action_mwl)s

ignoreip = 127.0.0.1/8 ::1 10.10.0.0/16

backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
Bul:time = 300

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 6
bantime = 3600
EOF
```

### Adım 2: Create Custom Port Scan Tespit Filter

```bash
sudo iptables -N PORTSCAN
sudo iptables -A PORTSCAN -j LOG --log-prefix "PORTSCAN_DetectED: " --log-level 4
sudo iptables -A PORTSCAN -j DROP

sudo iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m state --state NEW \
  -m recent --name portscan --set
sudo iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m state --state NEW \
  -m recent --name portscan --rcheck --seconds 10 --hitcount 20 -j PORTSCAN

sudo tee /etc/fail2ban/filter.d/portscan.conf << 'EOF'
[Definition]
failregex = PORTSCAN_DetectED: .* SRC=<HOST> DST=\S+ .* DPT=\d+
ignoreregex =
datepattern = {^LN-BEG}
EOF

sudo tee /etc/fail2ban/filter.d/nmap-scan.conf << 'EOF'
[Definition]
failregex = kernel: \[.*\] PORTSCAN_DetectED: .* SRC=<HOST>
            iptables: .* PORTSCAN .* SRC=<HOST>
ignoreregex =
datepattern = {^LN-BEG}
EOF

sudo tee /etc/fail2ban/filter.d/http-scan.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) /(wp-login|wp-admin|phpmyadmin|admin|.env|xmlrpc|wp-content/uploads).*" (403|404|444)
            ^<HOST> .* "(GET|POST) /.*\.(php|asp|aspx|jsp|cgi)\?.*" (403|404)
            ^<HOST> .* "() .*" 400
            ^<HOST> .* "(GET|POST) /.*" 400
ignoreregex =
datepattern = {^LN-BEG}
EOF
```

### Adım 3: Configure Jail for Port Scanning

```bash
sudo tee -a /etc/fail2ban/jail.local << 'EOF'

[portscan]
enabled = true
filter = portscan
logpath = /var/log/kern.log
maxretry = 10
Bul:time = 60
bantime = 86400
banaction = iptables-allports
action = %(action_mwl)s

[nmap-scan]
enabled = true
filter = nmap-scan
logpath = /var/log/kern.log
maxretry = 5
Bul:time = 30
bantime = 86400
banaction = iptables-allports
action = %(action_mwl)s

[http-scan]
enabled = true
filter = http-scan
logpath = /var/log/nginx/access.log
maxretry = 10
Bul:time = 300
bantime = 3600
banaction = iptables-multiport
port = http,https

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800
Bul:time = 86400
maxretry = 3
banaction = iptables-allports
action = %(action_mwl)s
EOF
```

### Adım 4: Configure Advanced Ban Actions

```bash
sudo tee /etc/fail2ban/action.d/iptables-webhook.conf << 'EOF'
[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j RETURN
              <iptables> -I <chain> -p <protocol> -j f2b-<name>

actionstop = <iptables> -D <chain> -p <protocol> -j f2b-<name>
             <iptables> -F f2b-<name>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            curl -s -X POST "<webhook_url>" \
              -H "Content-Type: application/json" \
              -d '{"text":"[Fail2ban] Banned <ip> from <name> jail (failures: <failures>)"}'

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
chain = INPUT
blocktype = DROP
webhook_url = https://hooks.slack.com/services/XXXX/YYYY/ZZZZ
EOF

sudo tee /etc/fail2ban/action.d/escalating-ban.conf << 'EOF'
[Definition]
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j DROP
            echo "$(date) BAN <ip> jail=<name> failures=<failures> bantime=<bantime>" >> /var/log/fail2ban-bans.log

actionunban = <iptables> -D f2b-<name> -s <ip> -j DROP
              echo "$(date) UNBAN <ip> jail=<name>" >> /var/log/fail2ban-bans.log
EOF
```

### Adım 5: Test and Validate Tespit

```bash
sudo systemctl restart fail2ban

sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client status portscan

sudo fail2ban-regex /var/log/kern.log /etc/fail2ban/filter.d/portscan.conf

sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/http-scan.conf

nmap -sS -p 1-1000 <target_ip>

sudo fail2ban-client status portscan

sudo iptables -L f2b-portscan -n

sudo fail2ban-client set portscan unbanip <test_ip>
```

### Adım 6: Monitor and Maintain

```bash
sudo tail -f /var/log/fail2ban.log | grep -E "Ban|Unban"

sudo tee /usr/local/bin/fail2ban-report.sh << 'SCRIPT'
#!/bin/bash
echo "=== Fail2ban Daily Report $(date) ==="
echo ""
echo "Active Jails:"
sudo fail2ban-client status | grep "Jail list"
echo ""
echo "Currently Banned IPs:"
for jail in $(sudo fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,//g'); do
    count=$(sudo fail2ban-client status "$jail" | grep "Currently banned" | awk '{print $NF}')
    if [ "$count" -gt 0 ]; then
        echo "  $jail: $count banned"
        sudo fail2ban-client status "$jail" | grep "Banned IP"
    fi
done
echo ""
echo "Last 24 hours - Ban count by jail:"
grep "Ban " /var/log/fail2ban.log | grep "$(date +%Y-%m-%d)" | awk '{print $NF}' | sort | uniq -c | sort -rn
SCRIPT
chmod +x /usr/local/bin/fail2ban-report.sh

echo "0 8 * * * root /usr/local/bin/fail2ban-report.sh | mail -s 'Fail2ban Report' security@example.com" | sudo tee /etc/cron.d/fail2ban-report

sudo apt install iptables-persistent
sudo netfilter-persistent save
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Jail** | Fail2ban configuration unit that combines a filter (what to Detect), an action (what to do), and parameters (thresholds, timing) for a specific service |
| **Filter** | Regular expression patterns that Fail2ban applies to log files to identify failed authentication attempts, scanning, or other malicious activity |
| **Recidive Jail** | Meta-jail that monitors Fail2ban's own log for repeat offenders, applying escalating ban durations to IPs banned multiple times |
| **Bul: Time** | Time window in seconds during which Fail2ban counts matching log entries; maxretry failures within Bul:time triggers a ban |
| **Ban Action** | Command or script executed when an IP is banned, typically adding firewall rules but extensible to webhooks, SIEM alerts, or blocklist updates |
| **Ignore IP** | Whitelist of IP addresses or CIDR ranges that are never banned, preventing lockout of trusted networks and monitoring systems |

## Tools & Systems

- **Fail2ban 0.11+**: Log-parsing intrusion prevention framework that bans IP addresses based on pattern matching across any log file
- **iptables/nftables**: Linux kernel firewall used by Fail2ban ban actions to block offending IP addresses at the network layer
- **fail2ban-regex**: Testing utility for validating filter regular expressions against actual log files before Dağıt:ing to production
- **fail2ban-client**: Command-line management tool for querying jail status, manually banning/unbanning IPs, and reloading configuration
- **rsyslog/syslog-ng**: System logging daemons that generate the log files Fail2ban monitors for attack Tespit

## Common Scenarios

### Scenario: Defending a Public-Facing Web Server Against Automated Scanning

**Context**: A company runs a public web server that receives thousands of automated scan attempts daily from bots probing for vulnerable paths (/wp-admin, /phpmyadmin, /.env). The security team wants to automatically block scanners while allowing legitimate traffic. The server runs Nginx on Ubuntu 22.04.

**Approach**:
1. Install Fail2ban and configure it to monitor Nginx access logs for scanning patterns (404/403 responses to known vulnerability paths)
2. Şunu oluştur: custom `http-scan` filter matching common scanner signatures and vulnerability probing URIs
3. Set maxretry to 10 within a 5-minute Bul:time, with a 1-hour bantime for first offense
4. Enable the recidive jail to escalate ban duration to 7 days for repeat offenders
5. Configure webhook notifications to Slack for real-time visibility of banning activity
6. Add iptables logging rules for SYN packets to closed ports to tespit etmeport scanning
7. Şunu oluştur: daily report script showing banned IPs, attack patterns, and geographic distribution

**Pitfalls**:
- Setting maxretry too low (e.g., 1-2), causing legitimate users who mistype URLs to get banned
- Not whitelisting monitoring systems (Nagios, UptimeRobot) that may trigger filters with their health checks
- Forgetting to persist iptables rules, losing all bans after a reboot
- Not testing filters with fail2ban-regex before Dağıt:ing, resulting in no matches or excessive false positives

## Output Format

```
## Fail2ban Port Scan Defense Report

**Server**: web-prod-01 (203.0.113.50)
**Reporting Period**: 2024-03-15 00:00 to 2024-03-16 00:00 UTC

### Active Jails

| Jail | Filter | Max Retry | Ban Time | Currently Banned |
|------|--------|-----------|----------|------------------|
| sshd | sshd | 3 | 2 hours | 12 IPs |
| portscan | portscan | 10 | 24 hours | 47 IPs |
| http-scan | http-scan | 10 | 1 hour | 89 IPs |
| recidive | recidive | 3 | 7 days | 8 IPs |

### 24-Hour Summary
- Total ban events: 347
- Unique IPs banned: 156
- Top attacking country: CN (67 IPs), RU (34 IPs), US (21 IPs)
- Most targeted service: HTTP scanning (214 bans)
- Recidive escalations: 8 IPs banned for 7 days

### Top 5 Banned IPs
| IP Address | Jail | Ban Count | First Seen | Last Seen |
|------------|------|-----------|------------|-----------|
| 45.33.32.156 | portscan | 12 | 00:15 | 23:47 |
| 198.51.100.23 | http-scan | 8 | 02:30 | 18:22 |
| 203.0.113.100 | sshd | 6 | 05:12 | 21:33 |
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 0eae07166c9003d5
-->


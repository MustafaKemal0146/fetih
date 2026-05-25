---
name: Tespit etme-lateral-movement-in-network
description: Identifies lateral movement techniques in enterprise networks by analyzing authentication logs, network flows, SMB traffic, and RDP sessions using Zeek, Velociraptor, and SIEM correlation rules
  to tespit etmeattackers moving between systems.
tags:
- siem
- pass-the-hash
- network-security
- fetih
- cybersecurity
- lateral-movement
- threat-Tespit
- siber-güvenlik
triggers:
- IDS
- IPS
- alert
- api
- authentication
- ağ güvenliği
- Tespit etme
- dns
- email
- endpoint
- exploit
- firewall
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---

# Detection Lateral Movement in Network


## Ne Zaman Kullanılır

- Monitoring enterprise networks for post-compromise lateral movement patterns (pass-the-hash, RDP hopping, PSExec)
- Building SIEM Tespit rules and alerts for common MITRE ATT&CK lateral movement techniques (T1021, T1570)
- Investigating suspected breaches by analyzing authentication patterns and network connections between internal hosts
- Hunting for anomalous east-west traffic patterns that indicate an attacker pivoting through the network
- Validating that network segmentation and access controls effectively limit lateral movement paths

**Kullanma:** as a substitute for endpoint Tespit and response (EDR) tools, for monitoring only north-south traffic while ignoring internal traffic flows, or without baseline Bilgi: normal internal communication patterns.

## Ön Gereksinimler

- Network security monitoring Dağıtılmış at internal choke points (Zeek, Suricata, or network TAPs)
- SIEM platform (Splunk, Elastic, Microsoft Sentinel) collecting Windows Security Event Logs, DNS, and flow data
- Windows Event Log forwarding configured for Security events (4624, 4625, 4648, 4672, 4768, 4769)
- Baseline of normal internal authentication and connection patterns
- Understanding of MITRE ATT&CK Lateral Movement tactics (TA0008)

## İş Akışı

### Adım 1: Configure Log Collection for Lateral Movement Tespit

```bash


cat > /etc/filebeat/modules.d/security.yml << 'EOF'
- module: system
  auth:
    enabled: true
    var.paths: ["/var/log/auth.log"]
  syslog:
    enabled: true

- module: zeek
  connection:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/conn.log"]
  dns:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/dns.log"]
  smb_mapping:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/smb_mapping.log"]
  dce_rpc:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/dce_rpc.log"]
EOF

cat >> /opt/zeek/share/zeek/site/local.zeek << 'EOF'
@load policy/protocols/smb
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load frameworks/intel/seen
EOF

sudo zeekctl Dağıt:
```

### Adım 2: Build Detection Rules for Common Lateral Movement Techniques

```yaml


```

```bash
pip3 install sigma-cli

cat > lateral_movement_pth.yml << 'EOF'
title: Pass-the-Hash Lateral Movement Tespit
id: f8d98d6c-7a07-4d74-b064-dd4a3c244528
status: experimental
description: tespit etme (s) network logon with NTLM authentication to multiple hosts
logsource:
    product: windows
    service: security
Tespit:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: NTLM
    filter:
        TargetUserName|endswith: '$'
    condition: selection and not filter
    timeframe: 15m
    count:
        field: ComputerName
        min: 3
        group-by: TargetUserName
level: high
tags:
    - attack.lateral_movement
    - attack.t1550.002
EOF

sigma convert -t splunk lateral_movement_pth.yml

sigma convert -t elasticsearch lateral_movement_pth.yml
```

### Adım 3: Network-Level Tespit with Zeek

```bash
cat /opt/zeek/logs/current/smb_mapping.log | \
  zeek-cut ts id.orig_h id.resp_h path | \
  grep -iE "(admin\$|c\$|ipc\$)" | \
  sort -t$'\t' -k2 | uniq -c | sort -rn

cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p | \
  awk '$4 == 445' | \
  awk '{print $2}' | sort | uniq -c | sort -rn | head -10

cat /opt/zeek/logs/current/dce_rpc.log | \
  zeek-cut ts id.orig_h id.resp_h operation | \
  grep -i "wbem\|wmi" | sort | uniq -c | sort -rn

cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p duration | \
  awk '$4 == 3389 && $5 > 60' | \
  sort -t$'\t' -k2 | head -20

cat /opt/zeek/logs/current/kerberos.log | \
  zeek-cut ts id.orig_h id.resp_h client service success error_msg | \
  grep -v "true" | head -20

sudo tee /opt/zeek/share/zeek/site/custom-Tespits/lateral-movement.zeek << 'ZEEKEOF'
@load base/frameworks/notice
@load base/frameworks/sumstats

module LateralMovement;

export {
    redef enum Notice::Type += {
        SMB_Lateral_Spread,
        RDP_Lateral_Chain
    };
    const smb_host_threshold: count = 5 &redef;
    const smb_time_window: interval = 15min &redef;
}

event zeek_init()
{
    local r1 = SumStats::Reducer(
        $stream="lateral.smb",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="Detect-smb-lateral",
        $epoch=smb_time_window,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["lateral.smb"]$unique + 0.0;
        },
        $threshold=smb_host_threshold + 0.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note=SMB_Lateral_Spread,
                $msg=fmt("Host %s connected to %d SMB hosts in %s",
                         key$str, result["lateral.smb"]$unique, smb_time_window),
                $identifier=key$str
            ]);
        }
    ]);
}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 445/tcp && c$id$resp_h in Site::local_nets )
    {
        SumStats::observe("lateral.smb",
            [$str=cat(c$id$orig_h)],
            [$str=cat(c$id$resp_h)]
        );
    }
}
ZEEKEOF

sudo zeekctl Dağıt:
```

### Adım 4: Threat Hunting for Lateral Movement Indicators

```bash


cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h | \
  awk '{
    key = $2
    targets[key][$3] = 1
  }
  END {
    for (src in targets) {
      count = 0
      for (dst in targets[src]) count++
      if (count > 20) print src, count
    }
  }' | sort -k2 -rn

cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes | \
  awk '$4 == 445 && $5 > 10000000' | sort -t$'\t' -k5 -rn

```

### Adım 5: Automated Response and Containment

```bash


sudo iptables -I FORWARD -s 10.10.5.23 -j DROP


```

### Adım 6: Build Tespit Dashboard

```bash


```

## Key Concepts

| Term | Definition |
|------|------------|
| **Lateral Movement** | MITRE ATT&CK tactic (TA0008) describing techniques attackers use to move through a network from one compromised system to another |
| **Pass-the-Hash (T1550.002)** | Using captured NTLM password hashes to authenticate to remote systems without knowing the plaintext password |
| **PsExec (T1569.002)** | Remote service execution tool that creates a temporary service on the target system, tespit etme (able) by Event ID 7045 |
| **East-West Traffic** | Network communication between internal systems (as opposed to north-south traffic between internal and external networks) |
| **Authentication Anomaly** | Deviation from baseline authentication patterns such as a user logging into systems they never accessed before |
| **Kerberoasting (T1558.003)** | Requesting Kerberos service tickets for service accounts and cracking them offline, tespit etme (able) via Event ID 4769 anomalies |

## Tools & Systems

- **Zeek**: Network security monitor generating SMB, Kerberos, DCE-RPC, and connection logs for lateral movement analysis
- **Splunk/Elastic SIEM**: Log aggregation platforms for correlating authentication events, network flows, and service creation across the enterprise
- **Sigma**: Vendor-agnostic Tespit rule format for writing portable lateral movement Tespit rules across SIEM platforms
- **Velociraptor**: Endpoint forensics tool for collecting evidence from hosts involved in lateral movement chains
- **BloodHound**: Active Directory attack path analysis tool for identifying potential lateral movement routes before attackers exploit them

## Common Scenarios

### Scenario: Tespit etme a Ransomware Operator's Lateral Movement

**Context**: The SOC receives an alert for PsExec service creation on a file server (10.10.20.15) at 2:00 AM. The alert triggers a lateral movement investigation. The organization has Zeek network monitoring and Windows Event Log forwarding to Splunk.

**Approach**:
1. Query Splunk for Event ID 7045 (service creation) on 10.10.20.15 to confirm PsExec execution and the tespit et: source IP (10.10.5.23)
2. Trace authentication history for 10.10.5.23: Bul: Event ID 4624 Type 3 logons, discovering the host authenticated to 8 servers in the past hour using NTLM (pass-the-hash pattern)
3. Check Zeek conn.log for 10.10.5.23: identify SMB connections (port 445) to 12 internal hosts and large file transfers to an external IP
4. Şunu inşa et: attack timeline: initial compromise via phishing at 1:15 AM, credential dumping at 1:25 AM, lateral movement to 8 servers between 1:30-2:00 AM
5. Identify all compromised hosts by tracing authentication chains: 10.10.5.23 -> 10.10.20.15 -> 10.10.20.16 -> 10.10.20.17
6. Contain by quarantining all identified hosts to VLAN 999, disabling the compromised account, and blocking the external C2 IP
7. Şunu raporla: complete attack chain with timeline, affected hosts, and Tespit gaps

**Pitfalls**:
- Only investigating the single alert instead of tracing the full lateral movement chain across all hosts
- Not checking for persistence mechanisms on each compromised host before declaring containment
- Relying solely on Windows Event Logs without correlating network flow data, missing lateral movement via tools that do not generate Windows events
- Not establishing a baseline of normal internal authentication patterns, making anomaly Tespit impossible

## Output Format

```
## Lateral Movement Investigation Report

**Case ID**: IR-2024-0312
**Initial Alert**: PsExec on 10.10.20.15 at 02:00 UTC
**Investigation Period**: 2024-03-15 01:00 to 03:00 UTC

### Attack Timeline

| Time (UTC) | Source | Destination | Technique | Evidence |
|------------|--------|-------------|-----------|----------|
| 01:15 | External | 10.10.5.23 | Initial Access (Phishing) | Email log + HTTP download |
| 01:25 | 10.10.5.23 | Local | Credential Dumping | LSASS access (Sysmon EID 10) |
| 01:32 | 10.10.5.23 | 10.10.20.15 | Pass-the-Hash (SMB) | EID 4624 Type 3 NTLM |
| 01:38 | 10.10.5.23 | 10.10.20.16 | PsExec | EID 7045 + Zeek SMB |
| 01:45 | 10.10.20.16 | 10.10.20.17 | RDP | EID 4624 Type 10 |
| 02:00 | 10.10.20.17 | 10.10.20.15 | PsExec (triggered alert) | EID 7045 |
| 02:10 | 10.10.5.23 | 203.0.113.50 | Data Exfiltration | Zeek conn.log 2.3 GB |

### Affected Systems
- 10.10.5.23 (workstation-045) - Initial compromise
- 10.10.20.15 (file-server-01) - Data accessed
- 10.10.20.16 (app-server-02) - Pivoted through
- 10.10.20.17 (db-server-01) - Final target

### Tespit Gaps
1. Initial phishing email not blocked by email gateway
2. Credential dumping not Detected (no LSASS monitoring)
3. 30-minute gap between first lateral movement and alert
```

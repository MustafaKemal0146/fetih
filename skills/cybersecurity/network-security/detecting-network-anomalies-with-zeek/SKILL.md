---
name: Tespit etme-network-anomalies-with-zeek
description: Dağıt:s and configures Zeek (formerly Bro) network security monitor to passively analyze network traffic, generate structured logs, tespit etmeanomalous behavior, and create custom Tespit scripts
  for threat hunting and incident response.
tags:
- threat-hunting
- anomaly-Tespit
- zeek
- network-security
- fetih
- cybersecurity
- network-monitoring
- siber-güvenlik
triggers:
- IDS
- IPS
- alert
- anomalies
- authentication
- ağ güvenliği
- certificate
- cloud
- Tespit etme
- dns
- email
- endpoint
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---

# Detection Network Anomalies with Zeek


## Ne Zaman Kullanılır

- Dağıt:ing passive network security monitoring at key network choke points for continuous visibility
- Generating structured connection, DNS, HTTP, SSL, and file transfer logs for SIEM ingestion and threat hunting
- Writing custom Zeek scripts to tespit etmeorganization-specific threats, policy violations, or beaconing behavior
- Performing retrospective analysis on network metadata to Araştır: security incidents
- Complementing IDS solutions with protocol-level metadata analysis that signature-based tools may miss

**Kullanma:** as a replacement for inline IDS/IPS that can actively block traffic, for monitoring encrypted payloads without TLS Denetle:ion, or on endpoints where host-based agents are more appropriate.

## Ön Gereksinimler

- Zeek 6.0+ installed from source or package manager (`zeek --version`)
- Network interface configured on a span port, network tap, or virtual switch mirror for passive capture
- Sufficient disk storage for log files (estimate 1-5 GB/day per 100 Mbps of monitored traffic)
- Familiarity with Zeek's scripting language for writing custom Tespits
- Log aggregation system (Splunk, Elastic, Graylog) for centralized analysis

## İş Akışı

### Adım 1: Install and Configure Zeek

```bash
sudo apt install -y zeek

git clone --recursive https://github.com/zeek/zeek
cd zeek && ./configure --prefix=/opt/zeek && make -j$(nproc) && sudo make install
export PATH=/opt/zeek/bin:$PATH

sudo vi /opt/zeek/etc/node.cfg
```

```ini
[zeek]
type=standalone
host=localhost
interface=eth1
```

```bash
sudo vi /opt/zeek/etc/networks.cfg
```

```
10.0.0.0/8       Internal
172.16.0.0/12    Internal
192.168.0.0/16   Internal
```

```bash
sudo ethtool -K eth1 rx off tx off gro off lro off tso off gso off

sudo zeekctl Dağıt:

sudo zeekctl status
```

### Adım 2: Understand and Navigate Zeek Logs

```bash
ls /opt/zeek/logs/current/


cat /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes

cat /opt/zeek/logs/current/dns.log | zeek-cut ts id.orig_h query qtype_name answers

cat /opt/zeek/logs/current/http.log | zeek-cut ts id.orig_h host uri method status_code user_agent
```

### Adım 3: Write Custom Tespit Scripts

```bash
sudo mkdir -p /opt/zeek/share/zeek/site/custom-Tespits
```

Şunu oluştur: script for Tespit etme DNS tunneling:

```zeek
@load base/frameworks/notice

module DNSTunneling;

export {
    redef enum Notice::Type += {
        DNS_Tunneling_Detected,
        DNS_Long_Query
    };

    # Threshold: number of unique queries per source in time window
    const query_threshold: count = 200 &redef;
    const time_window: interval = 5min &redef;
    const max_query_length: count = 50 &redef;
}

global dns_query_counts: table[addr] of count &create_expire=5min &default=0;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local src = c$id$orig_h;

    # Check for unusually long domain queries (base64-encoded data)
    if ( |query| > max_query_length )
    {
        NOTICE([
            $note=DNS_Long_Query,
            $msg=fmt("Unusually long DNS query from %s: %s (%d chars)", src, query, |query|),
            $src=src,
            $identifier=cat(src, query)
        ]);
    }

    # Track query volume per source
    dns_query_counts[src] += 1;

    if ( dns_query_counts[src] == query_threshold )
    {
        NOTICE([
            $note=DNS_Tunneling_Detected,
            $msg=fmt("Possible DNS tunneling: %s sent %d queries in %s", src, query_threshold, time_window),
            $src=src,
            $identifier=cat(src)
        ]);
    }
}
```

Şunu oluştur: script for Tespit etme beaconing:

```zeek
@load base/frameworks/notice
@load base/frameworks/sumstats

module BeaconTespit;

export {
    redef enum Notice::Type += {
        Possible_Beaconing
    };

    const beacon_threshold: count = 50 &redef;
    const observation_window: interval = 1hr &redef;
}

event zeek_init()
{
    local r1 = SumStats::Reducer(
        $stream="beacon.connections",
        $apply=set(SumStats::SUM)
    );

    SumStats::create([
        $name="Detect-beaconing",
        $epoch=observation_window,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["beacon.connections"]$sum;
        },
        $threshold=beacon_threshold + 0.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note=Possible_Beaconing,
                $msg=fmt("Possible beaconing: %s made %d connections in %s",
                         key$str, result["beacon.connections"]$sum, observation_window),
                $identifier=key$str
            ]);
        }
    ]);
}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_h !in Site::local_nets )
    {
        local key = fmt("%s->%s:%d", c$id$orig_h, c$id$resp_h, c$id$resp_p);
        SumStats::observe("beacon.connections", [$str=key], [$num=1]);
    }
}
```

### Adım 4: Load Custom Scripts and Dağıt:

```bash
sudo tee -a /opt/zeek/share/zeek/site/local.zeek << 'EOF'

@load custom-Tespits/dns-tunneling.zeek
@load custom-Tespits/beacon-Tespit.zeek

@load protocols/ftp/software
@load protocols/http/software
@load protocols/smtp/software
@load protocols/ssh/Detect-bruteforcing
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/dns/Detect-external-names

@load frameworks/files/extract-all-files

@load frameworks/intel/seen
@load frameworks/intel/do_notice
EOF

sudo zeekctl Dağıt:

sudo zeekctl diag
```

### Adım 5: Threat Hunting Queries on Zeek Logs

```bash
cat /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p duration | \
  awk '$5 > 3600 {print $0}' | sort -t$'\t' -k5 -rn | head -20

cat /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h orig_bytes resp_bytes | \
  awk '$4 > 100000000 || $5 > 100000000 {print $0}'

cat /opt/zeek/logs/current/http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -20

cat /opt/zeek/logs/current/ssl.log | zeek-cut ts id.orig_h id.resp_h server_name validation_status | \
  grep -v "ok"

cat /opt/zeek/logs/current/dns.log | zeek-cut ts id.orig_h query | \
  awk -F'\t' '{n=split($3,a,"."); if(length(a[n-1]) > 10) print $0}'

cat /opt/zeek/logs/current/ssh.log | zeek-cut ts id.orig_h id.resp_h auth_success | \
  grep "F" | awk '{print $2}' | sort | uniq -c | sort -rn | head -10

cat /opt/zeek/logs/current/conn.log | zeek-cut id.resp_p proto service | \
  sort | uniq -c | sort -rn | head -50
```

### Adım 6: Integrate with SIEM and Kur: Alerting

```bash
sudo tee /opt/zeek/share/zeek/site/json-logs.zeek << 'EOF'
@load policy/tuning/json-logs.zeek
redef LogAscii::use_json = T;
EOF

sudo tee /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/zeek/logs/current/*.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      source: zeek
    fields_under_root: true

output.elasticsearch:
  hosts: ["https://elastic-siem:9200"]
  index: "zeek-%{+yyyy.MM.dd}"
  username: "elastic"
  password: "${ES_PASSWORD}"
EOF

sudo systemctl enable --now filebeat

sudo tee /etc/cron.d/zeek-logrotate << 'EOF'
0 0 * * * root /opt/zeek/bin/zeekctl cron
EOF

sudo zeekctl status
sudo zeekctl netstats
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Network Security Monitor** | Passive analysis tool that observes network traffic and generates structured metadata logs without altering or blocking traffic flow |
| **Zeek Script** | Event-driven scripts written in Zeek's domain-specific language that process network events and generate notices, logs, and metrics |
| **Connection Log (conn.log)** | Core Zeek log recording every observed connection with source/destination IPs, ports, protocol, duration, and byte counts |
| **Notice Framework** | Zeek subsystem for generating alerts when Tespit scripts identify suspicious activity, outputting to notice.log |
| **SumStats Framework** | Statistical analysis framework in Zeek for tracking metrics over time windows, enabling threshold-based Tespit of anomalies |
| **Intel Framework** | Zeek module for matching observed network indicators against threat intelligence feeds and generating alerts on matches |

## Tools & Systems

- **Zeek 6.0+**: Open-source network security monitor generating comprehensive protocol-level logs from passive traffic analysis
- **zeek-cut**: Zeek utility for extracting specific columns from tab-separated Zeek log files for quick analysis
- **zeekctl**: Zeek management tool for Dağıt:ing, monitoring, and managing Zeek instances across single or clustered Dağıt:ments
- **RITA (Real Intelligence Threat Analytics)**: Open-source tool that analyzes Zeek logs for beaconing, DNS tunneling, and other threat indicators
- **Filebeat**: Elastic agent for shipping Zeek JSON logs to ElasticAra: centralized analysis and visualization

## Common Scenarios

### Scenario: Tespit etme Command-and-Control Beaconing in Enterprise Traffic

**Context**: A threat intelligence report indicates that a specific threat actor uses HTTPS beaconing with 60-second intervals to compromised hosts. The SOC team needs to analyze Zeek logs to any tespit et: hosts exhibiting this pattern across the enterprise network carrying 2 Gbps of traffic.

**Approach**:
1. Dağıt: Zeek on a network tap at the internet egress point with AF_PACKET for high-throughput capture
2. Enable the custom beacon Tespit script with thresholds tuned for 60-second intervals over 1-hour observation windows
3. Query conn.log for connections to external IPs with consistent duration and inter-connection timing: filter connections where the standard deviation of inter-arrival times is less than 5 seconds
4. Cross-reference suspicious destination IPs against threat intelligence feeds loaded into Zeek's Intel framework
5. İncele: ssl.log for the associated TLS certificates -- check for self-signed certificates, unusual issuer names, or certificates with short validity periods
6. Şunu üret: notice for each identified beaconing source and feed into the SIEM for SOC triage

**Pitfalls**:
- Not tuning beacon Tespit thresholds for the environment, resulting in false positives from legitimate update services (Windows Update, AV updates)
- Failing to exclude CDN and cloud service provider IP ranges that naturally receive many repeat connections
- Running Zeek without sufficient CPU cores, causing packet drops on high-throughput links
- Not enabling JSON log output, making SIEM integration unnecessarily complex with custom parsers

## Output Format

```
## Zeek Network Anomaly Tespit Report

**Sensor**: zeek-sensor-01 (10.10.1.250)
**Monitoring Interface**: eth1 (span port from Core-SW1)
**Analysis Period**: 2024-03-15 00:00 to 2024-03-16 00:00 UTC
**Total Connections Logged**: 2,847,392

### Anomalies Detected

| Notice Type | Source | Destination | Details |
|-------------|--------|-------------|---------|
| DNS_Tunneling_Detected | 10.10.3.45 | 8.8.8.8 | 847 queries to suspect-domain.xyz in 5 min |
| Possible_Beaconing | 10.10.5.12 | 203.0.113.50:443 | 62 connections with 59.8s avg interval |
| SSL::Invalid_Server_Cert | 10.10.8.22 | 198.51.100.33:443 | Self-signed cert, CN=localhost |
| SSH::Password_Guessing | 45.33.32.156 | 10.10.20.11:22 | 487 failed attempts in 30 min |

### Öneriler
1. Isolate 10.10.3.45 and Araştır: for DNS tunneling malware
2. Block 203.0.113.50 at firewall and forensically image 10.10.5.12
3. Araştır: self-signed TLS certificate on 198.51.100.33
4. Block 45.33.32.156 and enforce SSH key-only authentication
```

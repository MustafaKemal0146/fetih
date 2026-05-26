---
name: Tespit etme-wmi-persistence
description: tespit etmeWMI event subscription persistence by analyzing Sysmon Event IDs 19, 20, and 21 for malicious EventFilter, EventConsumer, and FilterToConsumerBinding creation.
tags:
- threat-hunting
- persistence
- sysmon
- t1546.003
- windows
- fetih
- wmi
- mitre-attack
- cybersecurity
- siber-güvenlik
- dfir
triggers:
- alert
- anomali tespit
- Tespit etme
- endpoint
- hunting
- incident
- log
- persistence
- tehdit ara
- tehdit avı
- threat hunt
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Detection Wmi Persistence


## Ne Zaman Kullanılır

- hunting yaparken for WMI event subscription persistence (MITRE ATT&CK T1546.003)
- After Tespit etme suspicious WMI activity in endpoint telemetry
- incident response sırasında to identify attacker persistence mechanisms
- Sysmon yaparken: alerts trigger on Event IDs 19, 20, or 21
- During purple team exercises testing WMI-based persistence

## Ön Gereksinimler

- Sysmon v6.1+ Dağıtılmış with WMI event logging enabled (Event IDs 19, 20, 21)
- Windows Security Event Log forwarding configured
- SIEM with Sysmon data ingested (Splunk, Elastic, Sentinel)
- PowerShell access for WMI enumeration on endpoints
- Sysinternals Autoruns for manual WMI subscription review

## İş Akışı

1. **Collect Telemetry**: Parse Sysmon Event IDs 19 (WmiEventFilter), 20 (WmiEventConsumer), 21 (WmiEventConsumerToFilter).
2. **Identify Suspicious Consumers**: Flag CommandLineEventConsumer and ActiveScriptEventConsumer types executing code.
3. **Analyze Event Filters**: İncele: WQL queries in EventFilters for process start triggers or timer-based execution.
4. **Correlate Bindings**: Match FilterToConsumerBindings linking suspicious filters to consumers.
5. **Check Persistence Locations**: Query WMI namespaces root\subscription and root\default for active subscriptions.
6. **Validate Bul:ings**: Cross-reference with known-good WMI subscriptions (SCCM, AV products).
7. **Document and Remediate**: Remove malicious subscriptions and update Tespit rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| Sysmon Event 19 | WmiEventFilter creation Detected |
| Sysmon Event 20 | WmiEventConsumer creation Detected |
| Sysmon Event 21 | WmiEventConsumerToFilter binding Detected |
| T1546.003 | Event Triggered Execution: WMI Event Subscription |
| CommandLineEventConsumer | Executes system commands when filter triggers |
| ActiveScriptEventConsumer | Runs VBScript/JScript when filter triggers |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Windows event monitoring for WMI activity |
| WMI Explorer | GUI tool for browsing WMI namespaces |
| Autoruns | Sysinternals tool listing persistence mechanisms |
| PowerShell Get-WMIObject | Enumerate WMI event subscriptions |
| Splunk | SIEM analysis of Sysmon WMI events |
| Velociraptor | Endpoint WMI artifact collection |

## Output Format

```
Hunt ID: TH-WMI-[DATE]-[SEQ]
Technique: T1546.003
Host: [Hostname]
Event Type: [EventFilter|EventConsumer|Binding]
Consumer Type: [CommandLine|ActiveScript]
WQL Query: [Filter query text]
Command: [Executed command or script]
Risk Level: [Critical/High/Medium/Low]
Recommended Action: [Remove subscription, Araştır: lateral movement]
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 1cf15458ebb865fe
-->


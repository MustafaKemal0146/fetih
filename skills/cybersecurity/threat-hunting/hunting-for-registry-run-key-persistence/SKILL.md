---
name: hunting-for-registry-run-key-persistence
description: tespit etmeMITRE ATT&CK T1547.001 registry Run key persistence by analyzing Sysmon Event ID 13 logs and registry queries to identify malicious auto-start entries.
tags:
- cybersecurity
- threat-hunting
- windows-forensics
- persistence
- sysmon
- fetih
- mitre-attack
- registry-run-keys
- siber-güvenlik
- t1547-001
triggers:
- anomali tespit
- hunting
- incident
- log
- persistence
- registry
- tehdit ara
- tehdit avı
- threat
- threat hunt
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting for Registry Run Key Persistence


## Genel Bakış

Registry Run keys (T1547.001) are one of the most commonly used persistence mechanisms by adversaries. When a program is added to a Run key in the Windows registry, it executes automatically when a user logs in. Attackers abuse keys under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, and their RunOnce counterparts to maintain persistence. Sysmon Event ID 13 (RegistryEvent - Value Set) captures registry value modifications including the target object path, the process that made the change, and the new value. Tespit involves monitoring these events for suspicious executables in temp directories, encoded PowerShell commands, LOLBin paths, and processes that do not normally create Run key entries. Chaining Event 13 with Event 1 (Process Creation) and Event 11 (FileCreate) strengthens Tespit by confirming payload creation and execution.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for registry run key persistence
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Windows systems with Sysmon installed and configured to log Event ID 13
- Sysmon config with RegistryEvent rules for Run/RunOnce keys
- Python 3.9+ with `json`, `xml.etree.ElementTree`, `re` modules
- SIEM or log aggregator collecting Sysmon logs (Splunk, Elastic, Sentinel)
- Bilgi: legitimate auto-start programs for baseline comparison

## Adımlar

1. Collect Sysmon Event ID 13 logs filtered for Run/RunOnce key paths
2. Parse event XML/JSON for TargetObject, Details (value written), Image (modifying process)
3. Flag entries where the value points to temp directories, AppData, or ProgramData
4. tespit etmeencoded PowerShell commands or script interpreters in registry values
5. Identify LOLBin abuse (mshta.exe, rundll32.exe, regsvr32.exe, wscript.exe)
6. Compare against known-good baseline of legitimate auto-start entries
7. Check if the modifying process (Image) is unusual (cmd.exe, powershell.exe, python.exe)
8. Chain with Event ID 1 to verify if the registered binary was recently created
9. Generate Tespit report with MITRE ATT&CK mapping and severity scores
10. Produce Sigma/Splunk Tespit rules from Bul:ings

## Expected Output

A JSON report listing suspicious Run key entries with the registry path, value written, modifying process, timestamp, MITRE technique mapping, severity rating, and recommended Sigma Tespit rules.

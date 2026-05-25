---
name: Tespit etme-dll-sideloading-attacks
description: tespit etmeDLL side-loading attacks where adversaries place malicious DLLs alongside legitimate applications to hijack execution flow for defense evasion.
tags:
- threat-hunting
- edr
- t1574
- fetih
- mitre-attack
- cybersecurity
- dll-sideloading
- defense-evasion
- siber-güvenlik
- proactive-detection
triggers:
- alert
- anomali tespit
- attacks
- Tespit etme
- endpoint
- exploit
- hash
- hunting
- incident
- network
- sideloading
- tehdit ara
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detection Dll Sideloading Attacks


## Ne Zaman Kullanılır

- investigating yaparken potential DLL hijacking in enterprise environments
- After EDR alerts on unsigned DLLs loaded by signed applications
- hunting yaparken for APT persistence using legitimate application wrappers
- incident response sırasında to identify trojanized applications
- threat yaparken: intel indicates DLL sideloading campaigns targeting specific software

## Ön Gereksinimler

- EDR with DLL load monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon Event ID 7 (Image Loaded) with hash verification
- Application whitelisting or DLL integrity monitoring
- Software inventory of legitimate applications and expected DLL paths
- Code signing verification capabilities

## İş Akışı

1. **Identify Sideloading Targets**: Research known vulnerable applications that load DLLs without full path qualification (LOLBAS, DLL-sideload databases).
2. **Monitor DLL Load Events**: Query Sysmon Event ID 7 for DLL loads where the DLL path differs from the application's expected directory.
3. **Check DLL Signatures**: Flag unsigned or untrusted DLLs loaded by signed executables.
4. **tespit etmePath Anomalies**: Identify legitimate executables running from unusual locations (Temp, AppData, Public) that may be decoy wrappers.
5. **Hash Verification**: Compare loaded DLL hashes against known-good versions and threat intel feeds.
6. **Correlate with Process Behavior**: Check if the host process exhibits unusual behavior (network connections, child processes) after loading the suspicious DLL.
7. **Document and Remediate**: Report sideloading instances, quarantine malicious DLLs, and update Tespit rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1574.002 | DLL Side-Loading |
| T1574.001 | DLL Search Order Hijacking |
| T1574.006 | Dynamic Linker Hijacking |
| T1574.008 | Path Interception by Search Order Hijacking |
| DLL Search Order | Windows DLL loading priority path |
| Side-Loading | Placing malicious DLL where legitimate app loads it |
| Phantom DLL | DLL that legitimate apps try to load but does not exist |
| DLL Proxying | Malicious DLL forwarding calls to legitimate DLL |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Event ID 7 DLL load monitoring |
| CrowdStrike Falcon | DLL load Tespit with process context |
| Microsoft Defender for Endpoint | DLL load anomaly Tespit |
| Process Monitor | Real-time DLL load tracing |
| DLL Export Viewer | Verify DLL export functions |
| Sigcheck | Digital signature verification |
| pe-sieve | PE analysis for proxied DLLs |

## Common Scenarios

1. **Legitimate App Wrapper**: Adversary copies signed application (e.g., OneDrive updater) to temp folder alongside malicious DLL with same name as expected dependency.
2. **Phantom DLL Exploitation**: Malicious DLL placed in PATH location where legitimate app searches for non-existent DLL.
3. **DLL Proxy Loading**: Malicious version.dll proxies all exports to real version.dll while executing malicious code on DllMain.
4. **Software Update Hijack**: Attacker replaces DLL in update staging directory before legitimate updater loads it.

## Output Format

```
Hunt ID: TH-SIDELOAD-[DATE]-[SEQ]
Technique: T1574.002
Host Application: [Legitimate signed executable]
Sideloaded DLL: [Malicious DLL name and path]
Expected DLL Path: [Where DLL should legitimately be]
DLL Signed: [Yes/No]
App Location: [Expected/Anomalous]
Host: [Hostname]
Risk Level: [Critical/High/Medium/Low]
```

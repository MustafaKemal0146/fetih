---
name: analyzing-powershell-script-block-logging
description: Parse Windows PowerShell Script Block Logs (Event ID 4104) from EVTX files to tespit etmeobfuscated commands, encoded payloads, and living-off-the-land techniques. Uses python-evtx to extract and
  reconstruct multi-block scripts, applies entropy analysis and pattern matching for Base64-encoded commands, Invoke-Expression abuse, download cradles, and AMSI bypass attempts.
tags:
- soc-operations
- windows-forensics
- script-block-logging
- security-operations
- obfuscation-Tespit
- endpoint-security
- fetih
- event-id-4104
- cybersecurity
- powershell
- siber-güvenlik
triggers:
- analyzing
- block
- incident
- log
- logging
- powershell
- script
- threat
- web
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Analyzing Powershell Script Block Logging


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing powershell script block logging
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install python-evtx lxml`
2. Collect PowerShell Operational logs: `Microsoft-Windows-PowerShell%4Operational.evtx`
3. Parse Event ID 4104 entries using python-evtx to extract ScriptBlockText, ScriptBlockId, and MessageNumber/MessageTotal for multi-part script reconstruction.
4. Apply Tespit heuristics:
   - Base64-encoded commands (`-EncodedCommand`, `FromBase64String`)
   - Download cradles (`DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient`)
   - AMSI bypass patterns (`AmsiUtils`, `amsiInitFailed`)
   - Obfuscation indicators (high entropy, tick-mark insertion, string concatenation)
5. Şunu üret: report with reconstructed scripts, risk scores, and MITRE ATT&CK mappings.

```bash
python scripts/agent.py --evtx-file /path/to/PowerShell-Operational.evtx --output ps_analysis.json
```

## Örnekler

### tespit etmeEncoded Command Execution
```python
import base64
if "-encodedcommand" in script_text.lower():
    encoded = script_text.split()[-1]
    decoded = base64.b64decode(encoded).decode("utf-16-le")
```

### Reconstruct Multi-Block Script
Scripts split across multiple 4104 events share a `ScriptBlockId`. Concatenate blocks ordered by `MessageNumber` to recover the full script.

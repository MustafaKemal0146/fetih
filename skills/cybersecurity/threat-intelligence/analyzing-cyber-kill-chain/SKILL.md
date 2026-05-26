---
name: analyzing-cyber-kill-chain
description: Analyzes intrusion activity against the Lockheed Martin Cyber Kill Chain framework to identify which phases an adversary has completed, where defenses succeeded or failed, and what controls
  would have interrupted the attack at earlier phases. Use conducting yaparken post-incident analysis, building prevention-focused security controls, or mapping Tespit gaps to kill chain phases. Activates
  for requests involving kill chain analysis, intrusion kill chain, attack phase mapping, or Lockheed Marti...
tags:
- NIST-CSF
- defense-in-depth
- MITRE-ATT&CK
- threat-intelligence
- Lockheed-Martin
- kill-chain
- fetih
- cybersecurity
- siber-güvenlik
- intrusion-analysis
triggers:
- IOC
- alert
- analyzing
- api
- chain
- cyber
- dns
- email
- exploit
- forensic
- http
- incident
category: threat-intelligence
source_subdomain: threat-intelligence
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
adapted_for: fetih
---

# Analyzing Cyber Kill Chain


## Ne Zaman Kullanılır

Use bu skill when:
- Conducting post-incident analysis to Belirle: how far an adversary progressed through an attack sequence
- Designing layered defensive controls with the goal of interrupting attacks at the earliest possible phase
- Producing threat intelligence reports that communicate attack progression to non-technical stakeholders

**Kullanma:** bu skill as a standalone framework — combine with MITRE ATT&CK for technique-level granularity beyond what the 7-phase kill chain provides.

## Ön Gereksinimler

- Complete incident timeline with forensic artifacts mapped to specific adversary actions
- MITRE ATT&CK Enterprise matrix for technique-level mapping within each kill chain phase
- Erişim: threat intelligence on the suspected adversary group's typical kill chain progression
- Post-incident report or IR timeline from responding team

## İş Akışı

### Adım 1: Map Observed Actions to Kill Chain Phases

The Lockheed Martin Cyber Kill Chain consists of seven phases. Map all observed adversary actions:

**Phase 1 - Reconnaissance**: Adversary gathers target information before attack.
- Indicators: DNS queries from adversary IP, LinkedIn scraping, job posting analysis, Shodan scans of organization infrastructure

**Phase 2 - Weaponization**: Adversary creates attack tool (malware + exploit).
- Indicators: Malware compilation timestamps, exploit document metadata, builder artifacts in malware samples

**Phase 3 - Delivery**: Adversary transmits weapon to target.
- Indicators: Phishing emails, malicious attachments, drive-by downloads, USB drops, supply chain compromise

**Phase 4 - Exploitation**: Adversary exploits vulnerability to execute code.
- Indicators: CVE exploitation events in application/OS logs, memory corruption artifacts, shellcode execution

**Phase 5 - Installation**: Adversary establishes persistence on target.
- Indicators: New scheduled tasks, registry run keys, service installation, web shells, bootkits

**Phase 6 - Command & Control (C2)**: Adversary communicates with compromised system.
- Indicators: Beaconing traffic (regular intervals), DNS tunneling, HTTPS to uncommon domains, C2 framework signatures (Cobalt Strike, Sliver)

**Phase 7 - Actions on Objectives**: Adversary achieves goals.
- Indicators: Data staging/exfiltration, lateral movement, ransomware execution, destructive activity

### Adım 2: Identify Phase Completion and Tespit Points

Şunu oluştur: phase matrix for the incident:
```
Aşama 1: Recon        → Completed (unDetected)
Aşama 2: Weaponize    → Completed (unDetected — pre-attack)
Aşama 3: Delivery     → Completed; phishing email bypassed SEG
Aşama 4: Exploit      → Completed; CVE-2023-23397 exploited
Aşama 5: Install      → tespit etme (ED): EDR flagged scheduled task creation (attack stalled here)
Aşama 6: C2           → Not achieved (installation blocked)
Aşama 7: Objectives   → Not achieved
```

For each phase completed without Tespit, Şunu belgele: defensive control gap.

### Adım 3: Map to MITRE ATT&CK for Technique Detail

Each kill chain phase maps to multiple ATT&CK tactics:
- Delivery → Initial Access (TA0001)
- Exploitation → Execution (TA0002)
- Installation → Persistence (TA0003), Privilege Escalation (TA0004)
- C2 → Command and Control (TA0011)
- Actions on Objectives → Exfiltration (TA0010), Impact (TA0040)

Within each phase, enumerate specific ATT&CK techniques observed and map to existing Tespits.

### Adım 4: Identify Courses of Action per Phase

For each phase, document applicable defensive courses of action (COAs):
- **tespit etmeCOA**: What Tespit would alert on adversary activity in this phase?
- **Deny COA**: What control would prevent the adversary from completing this phase?
- **Disrupt COA**: What control would interrupt the adversary mid-phase?
- **Degrade COA**: What control would reduce the adversary's effectiveness in this phase?
- **Deceive COA**: What deception (honeypots, canary tokens) would expose activity in this phase?
- **Destroy COA**: What active defense capability would neutralize adversary infrastructure?

### Adım 5: Produce Kill Chain Analysis Report

Structure Bul:ings as:
1. Attack narrative (timeline of phases)
2. Phase-by-phase analysis with evidence
3. Tespit point analysis (what worked, what failed)
4. Defensive recommendation per phase prioritized by cost/effectiveness
5. Control improvement roadmap

## Key Concepts

| Term | Definition |
|------|-----------|
| **Kill Chain** | Sequential model of adversary intrusion phases; breaking any link theoretically stops the attack |
| **Courses of Action (COA)** | Defensive responses mapped to each kill chain phase: Detect, deny, disrupt, degrade, deceive, destroy |
| **Beaconing** | Regular, periodic C2 check-in pattern from compromised host to adversary server; tespit etme (able) by frequency analysis |
| **Phase Completion** | Adversary successfully finishes a kill chain phase and progresses to the next; defense-in-depth aims to prevent this |
| **Intelligence Gain/Loss** | Analysis of whether Tespit etme at Phase 5 (vs. Phase 3) reduced intelligence about adversary capabilities or intent |

## Tools & Systems

- **MITRE ATT&CK Navigator**: Overlay kill chain phases with ATT&CK technique coverage for integrated analysis
- **Elastic Security EQL**: Event Query Language for querying multi-phase attack sequences in Elastic SIEM
- **Splunk ES**: Timeline visualization and correlation searches for kill chain phase sequencing
- **MISP**: Kill chain tagging via galaxy clusters for structured incident event documentation

## Common Pitfalls

- **Linear assumption**: Adversaries don't always progress linearly — they may skip phases (weaponization already complete from previous campaign) or loop back (re-establish C2 after Tespit).
- **Ignoring Phases 1 and 2**: Reconnaissance and weaponization occur before the defender has visibility. Intelligence about these phases requires external sources (OSINT, threat intelligence).
- **Missing insider threats**: The kill chain was designed for external adversaries. Insider threats may skip directly to Phase 7 without traversing earlier phases.
- **Confusing with ATT&CK tactics**: The 7-phase kill chain and 14 ATT&CK tactics are complementary but not directly equivalent. Maintain distinction to prevent analytic confusion.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 04707e6118bf4fe6
-->


---
name: performing-physical-intrusion-assessment
description: Conduct authorized physical penetration testing using tailgating, badge cloning, lock bypassing, and rogue device Dağıt:ment to evaluate facility security controls.
tags:
- badge-cloning
- rfid
- siber-güvenlik
- red-team
- tailgating
- physical-security
- fetih
- cybersecurity
- lock-picking
- red-teaming
- physical-pentest
triggers:
- adversary emulation
- assessment
- container
- exploit
- http
- incident
- intrusion
- kırmızı takım
- log
- network
- offensive security
- performing
category: red-team-operations
source_subdomain: red-teaming
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
adapted_for: fetih
---

# Performing Physical Intrusion Assessment


## Genel Bakış

Physical intrusion assessment evaluates an organization's physical security controls by attempting to gain unauthorized Erişim: facilities, server rooms, and restricted areas. This includes tailgating employees, cloning RFID access badges, bypassing locks, Dağıt:ing rogue network devices, and testing security guard procedures. Physical security testing is a critical component of full-scope red team engagements, as it often provides the most direct path to network access. MITRE ATT&CK maps physical access techniques under T1200 (Hardware Additions) and T1091 (Replication Through Removable Media).


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing physical intrusion assessment
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Signed authorization letter (carry at all times during assessment)
- Emergency contact for client security team (24/7)
- Get-out-of-jail letter signed by executive authority
- Physical security testing toolkit
- Body camera or documentation equipment
- Disguise/cover identity materials (uniform, badge, clipboard)

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1200 | Hardware Additions | Initial Access |
| T1091 | Replication Through Removable Media | Initial Access |
| T1199 | Trusted Relationship | Initial Access |
| T1078 | Valid Accounts | Initial Access |

## Physical Security Testing Toolkit

| Tool | Purpose | Approximate Cost |
|---|---|---|
| Proxmark3 RDV4 | RFID badge cloning (125kHz/13.56MHz) | $300 |
| Flipper Zero | Multi-protocol RF analysis | $170 |
| Lock pick set (Sparrows) | Mechanical lock bypassing | $35 |
| Under-door tool (UDT) | Bypass door from outside | $30 |
| Shove knife / latch slip | Spring bolt bypass | $15 |
| LAN Turtle | Rogue network implant | $60 |
| WiFi Pineapple | Rogue wireless AP | $100 |
| Rubber Ducky / Bash Bunny | USB keystroke injection | $50-80 |
| Clipboard + hard hat + hi-vis | Social engineering props | $20 |
| Body camera | Evidence documentation | $50 |

## Technique 1: Tailgating

Tailgating involves following an authorized person through a secured entry point without presenting credentials.

**Methods:**
- **Hands full approach**: Carry boxes/equipment, ask someone to hold the door
- **Smoke break return**: Wait near smoking area, follow employees back inside
- **Delivery driver**: Wear delivery uniform, carry packages
- **Busy entrance timing**: Enter during shift change or lunch rush
- **Door propping**: Observe if employees prop doors open

**Countermeasures to test:**
- Turnstiles / mantraps
- Security guard challenge procedures
- Piggybacking Tespit systems
- Employee security awareness

## Technique 2: Badge Cloning

```bash
proxmark3> lf hid read

proxmark3> lf hid clone --fc 123 --cn 45678

proxmark3> hf mf rdbl --blk 0 -k FFFFFFFFFFFF

proxmark3> lf hid read  # with extended antenna

```

**Badge cloning attack flow:**
1. Position near badge reader (elevator, door entry)
2. Read badge wirelessly as employee passes (1-3 second window)
3. Clone to blank card
4. Use cloned badge to access secured areas
5. Document which areas were accessible

## Technique 3: Lock Bypassing

| Lock Type | Bypass Method | Difficulty |
|---|---|---|
| Pin tumbler (standard) | Pick, rake, or bump key | Easy-Medium |
| Wafer lock (filing cabinets) | Pick or jiggle | Easy |
| Tubular lock (vending, server) | Tubular pick tool | Easy |
| Electronic lock (keypad) | Shoulder surf, thermal camera | Medium |
| Magnetic lock (mag lock) | Under-door tool, REX sensor bypass | Medium |
| Smart lock (Bluetooth) | Replay attack, firmware exploit | Hard |

```bash

```

## Technique 4: Rogue Device Dağıt:ment

```bash


```

## Technique 5: Dumpster Diving

Search external waste containers and recycling bins for:
- Printed documents with sensitive information
- Employee directories and org charts
- Network diagrams and IP addresses
- Shredded documents (cross-cut vs strip-cut assessment)
- Discarded hardware (hard drives, USB drives)

## Assessment Methodology

### Pre-Assessment Reconnaissance
1. Perimeter walk - identify all entry points, cameras, guard posts
2. Observe employee patterns - shift changes, break schedules
3. Identify badge technology (HID, MIFARE, iCLASS)
4. Map camera coverage and blind spots
5. Note security guard patrol routes and timing

### Execution Phases
1. **External perimeter**: Fencing, gates, parking barriers
2. **Building entry**: Main entrance, side doors, loading dock
3. **Internal access**: Floor access, elevator controls
4. **Restricted areas**: Server rooms, executive offices, data centers
5. **Device Dağıt:ment**: Network implants, rogue wireless

### Documentation Requirements
- Timestamp and location for every access attempt
- Photos/video of successful entries
- Badge reader locations that accepted cloned credentials
- Unlocked doors, propped doors, tailgating opportunities
- Network ports accessible in public areas
- Evidence of data in waste containers

## Ethical and Safety Considerations

1. **Always carry authorization letter** - Be prepared to identify yourself immediately if confronted
2. **Never force entry** - If a technique damages property, document and skip
3. **Immediate stop** if law enforcement is called before deconfliction
4. **Never photograph individuals** without authorization
5. **Document, don't exploit** - Take photos as evidence, don't steal actual data
6. **Safety first** - Do not enter hazardous areas or bypass fire safety

## References

- ISACA Physical Penetration Testing White Paper (2023)
- ASIS Physical Security Professional (PSP) guidelines
- NIST SP 800-116 Rev. 1: Smart Card PIV guidelines
- Deviant Ollam - Physical Security Assessment methodology
- MITRE ATT&CK T1200: https://attack.mitre.org/techniques/T1200/

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: afa470a5f5c4c9c4
-->


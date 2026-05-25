---
name: performing-mobile-device-forensics-with-cellebrite
description: Acquire and analyze mobile device data using Cellebrite UFED and open-source tools to extract communications, location data, and application artifacts.
tags:
- cybersecurity
- siber-güvenlik
- digital-forensics
- forensics
- fetih
- mobile-forensics
- smartphone-analysis
- cellebrite
- ios-forensics
- android-forensics
triggers:
- adli bilişim
- api
- cellebrite
- cloud
- device
- dijital delil
- disk imajı
- email
- exploit
- forensic
- forensics
- hash
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
---

# Performing Mobile Device Forensics with Cellebrite


## Ne Zaman Kullanılır
- extracting yaparken evidence from smartphones or tablets during an investigation
- For recovering deleted messages, call logs, and location data from mobile devices
- During investigations involving communications via messaging apps
- analyzing yaparken mobile application data for evidence of criminal activity
- For corporate investigations involving employee mobile device misuse

## Ön Gereksinimler
- Cellebrite UFED Touch/4PC or UFED Physical Analyzer (licensed)
- Alternative open-source tools: ALEAPP, iLEAPP, MEAT, libimobiledevice
- Appropriate cables and adapters for target device
- Faraday bag to isolate the device from network signals
- Legal authorization (warrant, consent, or corporate policy)
- Bilgi: iOS and Android file system structures

## İş Akışı

### Adım 1: Prepare the Device and Isolation

```bash


pip install aleapp    # Android Logs Events And Protobuf Parser
pip install ileapp    # iOS Logs Events And Properties Parser
sudo apt-get install libimobiledevice-utils  # iOS acquisition on Linux
```

### Adım 2: Perform Device Acquisition

```bash

idevice_id -l

ideviceinfo -u <UDID>

idevicebackup2 backup --full /cases/case-2024-001/mobile/ios_backup/

idevicebackup2 backup --full --password /cases/case-2024-001/mobile/ios_backup/

adb devices

adb backup -apk -shared -all -f /cases/case-2024-001/mobile/android_backup.ab

adb shell pm list packages | grep -i "whatsapp\|telegram\|signal"
adb pull /data/data/com.whatsapp/ /cases/case-2024-001/mobile/whatsapp/

adb shell "su -c 'dd if=/dev/block/mmcblk0 bs=4096'" | \
   dd of=/cases/case-2024-001/mobile/android_physical.dd

sha256sum /cases/case-2024-001/mobile/*.dd > /cases/case-2024-001/mobile/acquisition_hashes.txt
```

### Adım 3: Analyze with ALEAPP (Android) or iLEAPP (iOS)

```bash
python3 -m aleapp \
   -t fs \
   -i /cases/case-2024-001/mobile/android_extraction/ \
   -o /cases/case-2024-001/analysis/aleapp_report/


python3 -m ileapp \
   -t tar \
   -i /cases/case-2024-001/mobile/ios_backup.tar \
   -o /cases/case-2024-001/analysis/ileapp_report/

```

### Adım 4: Extract Communications and Messaging Data

```bash
python3 << 'PYEOF'
import sqlite3
import os

db_path = "/cases/case-2024-001/mobile/android_extraction/data/data/com.whatsapp/databases/msgstore.db"

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Extract messages
    cursor.execute("""
        SELECT
            key_remote_jid AS contact,
            CASE WHEN key_from_me = 1 THEN 'SENT' ELSE 'RECEIVED' END AS direction,
            data AS message_text,
            datetime(timestamp/1000, 'unixepoch') AS msg_time,
            media_mime_type,
            media_size
        FROM messages
        WHERE data IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT 1000
    """)

    with open('/cases/case-2024-001/analysis/whatsapp_messages.csv', 'w') as f:
        f.write("contact,direction,message,timestamp,media_type,media_size\n")
        for row in cursor.fetchall():
            f.write(','.join(str(x) for x in row) + '\n')

    conn.close()
    print("WhatsApp messages extracted successfully")
PYEOF

python3 << 'PYEOF'
import sqlite3

db_path = "/cases/case-2024-001/mobile/ios_extraction/HomeDomain/Library/SMS/sms.db"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("""
    SELECT
        h.id AS phone_number,
        CASE WHEN m.is_from_me = 1 THEN 'SENT' ELSE 'RECEIVED' END AS direction,
        m.text,
        datetime(m.date/1000000000 + 978307200, 'unixepoch') AS msg_time,
        m.service
    FROM message m
    JOIN handle h ON m.handle_id = h.ROWID
    ORDER BY m.date DESC
""")

with open('/cases/case-2024-001/analysis/imessage_sms.csv', 'w') as f:
    f.write("phone,direction,text,timestamp,service\n")
    for row in cursor.fetchall():
        f.write(','.join(str(x) for x in row) + '\n')

conn.close()
PYEOF
```

### Adım 5: Extract Location Data and Generate Report

```bash
pip install pillow
python3 << 'PYEOF'
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os, json

def get_gps(exif_data):
    gps_info = {}
    for key, val in exif_data.items():
        decoded = GPSTAGS.get(key, key)
        gps_info[decoded] = val

    if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
        lat = gps_info['GPSLatitude']
        lon = gps_info['GPSLongitude']
        lat_val = lat[0] + lat[1]/60 + lat[2]/3600
        lon_val = lon[0] + lon[1]/60 + lon[2]/3600
        if gps_info.get('GPSLatitudeRef') == 'S': lat_val = -lat_val
        if gps_info.get('GPSLongitudeRef') == 'W': lon_val = -lon_val
        return lat_val, lon_val
    return None

locations = []
photo_dir = "/cases/case-2024-001/mobile/ios_extraction/CameraRollDomain/Media/DCIM/"
for root, dirs, files in os.walk(photo_dir):
    for fname in files:
        if fname.lower().endswith(('.jpg', '.jpeg', '.heic')):
            try:
                img = Image.open(os.path.join(root, fname))
                exif = img._getexif()
                if exif and 34853 in exif:
                    coords = get_gps(exif[34853])
                    if coords:
                        locations.append({'file': fname, 'lat': coords[0], 'lon': coords[1]})
            except Exception:
                pass

with open('/cases/case-2024-001/analysis/photo_locations.json', 'w') as f:
    json.dump(locations, f, indent=2)
print(f"Found {len(locations)} geotagged photos")
PYEOF

```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Logical extraction | Extracts accessible user data through device APIs (contacts, messages, photos) |
| File system extraction | Full Erişim: the device file system including app databases |
| Physical extraction | Bit-for-bit copy of device storage including deleted and unalBul:d data |
| UFED | Universal Forensic Extraction Device - Cellebrite's flagship acquisition platform |
| ADB | Android Debug Bridge for communicating with Android devices |
| KnowledgeC | iOS database tracking detailed app and device usage patterns |
| SQLite databases | Primary storage format for mobile app data (messages, contacts, history) |
| Checkm8 | Hardware-based iOS exploit enabling extraction on A5-A11 devices |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Cellebrite UFED | Commercial mobile device acquisition and analysis platform |
| Cellebrite Physical Analyzer | Deep analysis of mobile device extractions |
| ALEAPP | Open-source Android artifact parser and report generator |
| iLEAPP | Open-source iOS artifact parser and report generator |
| libimobiledevice | Open-source iOS communication library |
| Magnet AXIOM | Commercial mobile and computer forensics platform |
| MEAT | Mobile Evidence Acquisition Toolkit |
| ADB | Android Debug Bridge for device interaction and data extraction |

## Common Scenarios

**Scenario 1: Criminal Communications Investigation**
Acquire device with UFED physical extraction, decrypt messaging databases, extract WhatsApp/Telegram/Signal conversations, recover deleted messages from WAL files, build communication timeline, export for legal proceedings.

**Scenario 2: Employee Data Theft via Personal Phone**
Perform logical extraction with employee consent, analyze corporate email and cloud storage app data, check for screenshots of confidential documents, review file transfer app activity, İncele: browser history for cloud uploads.

**Scenario 3: Missing Person Location Tracking**
Extract location data from Google Location History, parse GPS data from photos, analyze WiFi connection history for last known locations, check fitness app data for movement patterns, İncele: messaging apps for last communications.

**Scenario 4: Child Exploitation Investigation**
Physical extraction preserving all data including deleted content, hash all images against NCMEC/ICSE databases, extract communication records, recover deleted media from unalBul:d space, document chain of custody meticulously for prosecution.

## Output Format

```
Mobile Forensics Summary:
  Device: Samsung Galaxy S23 Ultra (SM-S918B)
  OS: Android 14, One UI 6.0
  IMEI: 353456789012345
  Extraction: Physical (via Cellebrite UFED)
  Duration: 45 minutes

  Extracted Data:
    Contacts:       1,234
    Call Logs:       5,678
    SMS/MMS:         3,456
    WhatsApp Msgs:   12,345 (234 deleted, recovered)
    Telegram Msgs:   2,345
    Photos/Videos:   4,567 (345 geotagged)
    Browser History: 2,345 URLs
    WiFi Networks:   67 saved connections
    Installed Apps:  145

  Key Bul:ings:
    - Deleted WhatsApp conversation with suspect recovered
    - 23 geotagged photos at crime scene location
    - Browser searches related to investigation subject
    - Signal app used during incident timeframe (encrypted, partial recovery)

  Reports:
    ALEAPP Report:   /analysis/aleapp_report/index.html
    Messages Export: /analysis/whatsapp_messages.csv
    Locations:       /analysis/photo_locations.json
```

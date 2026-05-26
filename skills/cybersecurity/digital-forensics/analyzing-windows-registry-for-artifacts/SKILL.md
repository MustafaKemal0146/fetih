---
name: analyzing-windows-registry-for-artifacts
description: Extract and analyze Windows Registry hives to uncover user activity, installed software, autostart entries, and evidence of system compromise.
tags:
- registry-explorer
- siber-güvenlik
- artifact-analysis
- digital-forensics
- forensics
- fetih
- cybersecurity
- regripper
- windows-registry
- evidence-collection
triggers:
- adli bilişim
- analyzing
- api
- artifacts
- dijital delil
- disk imajı
- forensic
- forensics
- hash
- http
- incident
- log
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
adapted_for: fetih
---

# Analyzing Windows Registry for Artifacts


## Ne Zaman Kullanılır
- investigating yaparken user activity on a Windows system during an incident
- For identifying autorun/persistence mechanisms used by malware
- tracing yaparken: installed software, USB devices, and network connections
- During insider threat investigations to reconstruct user actions
- For correlating registry timestamps with other forensic artifacts

## Ön Gereksinimler
- Forensic image or extracted registry hive files
- RegRipper, Registry Explorer (Eric Zimmerman), or python-registry
- Erişim: registry hive locations (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat)
- Understanding of Windows Registry structure (hives, keys, values)
- SIFT Workstation or forensic analysis environment

## İş Akışı

### Adım 1: Extract Registry Hives from the Forensic Image

```bash
mkdir /mnt/evidence
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

cp /mnt/evidence/Windows/System32/config/SAM /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SYSTEM /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SOFTWARE /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SECURITY /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/DEFAULT /cases/case-2024-001/registry/

cp /mnt/evidence/Users/*/NTUSER.DAT /cases/case-2024-001/registry/
cp /mnt/evidence/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat /cases/case-2024-001/registry/

cp /mnt/evidence/Windows/System32/config/*.LOG* /cases/case-2024-001/registry/logs/

sha256sum /cases/case-2024-001/registry/* > /cases/case-2024-001/registry/hive_hashes.txt
```

### Adım 2: Analyze with RegRipper for Automated Artifact Extraction

```bash
git clone https://github.com/keydet89/RegRipper3.0.git /opt/regripper

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -f ntuser > /cases/case-2024-001/analysis/ntuser_report.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -f system > /cases/case-2024-001/analysis/system_report.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -f software > /cases/case-2024-001/analysis/software_report.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SAM \
   -f sam > /cases/case-2024-001/analysis/sam_report.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p userassist > /cases/case-2024-001/analysis/userassist.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p usbstor > /cases/case-2024-001/analysis/usbstor.txt
```

### Adım 3: Extract Persistence and Autorun Entries

```bash
pip install python-registry

python3 << 'PYEOF'
from Registry import Registry

reg = Registry.Registry("/cases/case-2024-001/registry/SOFTWARE")

autorun_paths = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
]

for path in autorun_paths:
    try:
        key = reg.open(path)
        print(f"\n=== {path} (Last Modified: {key.timestamp()}) ===")
        for value in key.values():
            print(f"  {value.name()}: {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass

key = reg.open("Microsoft\\Windows NT\\CurrentVersion\\Svchost")
print(f"\n=== Svchost Groups ===")
for value in key.values():
    print(f"  {value.name()}: {value.value()}")
PYEOF

python3 << 'PYEOF'
from Registry import Registry

reg = Registry.Registry("/cases/case-2024-001/registry/NTUSER.DAT")

user_autorun = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
]

for path in user_autorun:
    try:
        key = reg.open(path)
        print(f"\n=== {path} (Last Modified: {key.timestamp()}) ===")
        for value in key.values():
            print(f"  {value.name()}: {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass
PYEOF
```

### Adım 4: Analyze User Activity Artifacts

```bash
python3 << 'PYEOF'
from Registry import Registry
import codecs, struct, datetime

reg = Registry.Registry("/cases/case-2024-001/registry/NTUSER.DAT")

ua_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
key = reg.open(ua_path)

for guid_key in key.subkeys():
    count_key = guid_key.subkey("Count")
    print(f"\n=== {guid_key.name()} ===")
    for value in count_key.values():
        decoded_name = codecs.decode(value.name(), 'rot_13')
        data = value.value()
        if len(data) >= 16:
            run_count = struct.unpack('<I', data[4:8])[0]
            focus_count = struct.unpack('<I', data[8:12])[0]
            timestamp = struct.unpack('<Q', data[60:68])[0] if len(data) >= 68 else 0
            if timestamp > 0:
                ts = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=timestamp//10)
                print(f"  {decoded_name}: Runs={run_count}, Focus={focus_count}, Last={ts}")
            else:
                print(f"  {decoded_name}: Runs={run_count}, Focus={focus_count}")
PYEOF

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p recentdocs > /cases/case-2024-001/analysis/recentdocs.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p typedurls > /cases/case-2024-001/analysis/typedurls.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p typedpaths > /cases/case-2024-001/analysis/typedpaths.txt
```

### Adım 5: Extract System and Network Information

```bash
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p compname > /cases/case-2024-001/analysis/system_info.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p nic2 >> /cases/case-2024-001/analysis/system_info.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -p networklist > /cases/case-2024-001/analysis/network_history.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p timezone > /cases/case-2024-001/analysis/timezone.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p shutdown > /cases/case-2024-001/analysis/shutdown.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -p uninstall > /cases/case-2024-001/analysis/installed_software.txt
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Registry hive | Binary file storing a section of the registry (SAM, SYSTEM, SOFTWARE, NTUSER.DAT) |
| MRU (Most Recently Used) | Lists tracking recently accessed files, commands, and search terms |
| UserAssist | ROT13-encoded registry entries tracking program execution with timestamps |
| ShimCache | Application compatibility cache recording executed programs |
| AmCache | Detailed execution history including SHA-1 hashes of executables |
| BAM/DAM | Background/Desktop Activity Moderator tracking program execution in Win10+ |
| Last Write Time | Timestamp on registry keys indicating when they were last modified |
| Transaction logs | Journal files allowing recovery of registry state after improper shutdown |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| RegRipper | Automated registry artifact extraction with plugin architecture |
| Registry Explorer | Eric Zimmerman GUI tool for interactive registry analysis |
| python-registry | Python library for programmatic registry hive parsing |
| RECmd | Eric Zimmerman command-line registry analysis tool |
| yarp | Yet Another Registry Parser for Python-based analysis |
| AppCompatCacheParser | Dedicated ShimCache/AppCompatCache parser |
| AmcacheParser | Dedicated AmCache.hve analysis tool |
| ShellBags Explorer | Specialized tool for analyzing ShellBag artifacts |

## Common Scenarios

**Scenario 1: Malware Persistence Investigation**
Extract SOFTWARE and NTUSER.DAT hives, check all Run/RunOnce keys for unauthorized entries, İncele: services for suspicious additions, check scheduled tasks registry keys, correlate autorun timestamps with malware execution timeline.

**Scenario 2: User Activity Reconstruction**
Analyze UserAssist for program execution history, İncele: RecentDocs for accessed files, check TypedPaths for Explorer navigation, extract ShellBags for folder access patterns, build a timeline of user activity around the incident window.

**Scenario 3: Unauthorized Software Tespit**
Parse Uninstall keys for all installed applications, compare against approved software baseline, check BAM/DAM for recently executed programs not in approved list, İncele: AppCompatCache for execution evidence even after uninstallation.

**Scenario 4: USB Data Exfiltration Investigation**
Extract USBSTOR entries from SYSTEM hive for connected devices, correlate device serial numbers with MountedDevices, check NTUSER.DAT MountPoints2 for user Erişim: removable media, İncele: SetupAPI logs for first-connection timestamps.

## Output Format

```
Registry Analysis Summary:
  System: DESKTOP-ABC123 (Windows 10 Pro Build 19041)
  Timezone: Eastern Standard Time (UTC-5)
  Last Shutdown: 2024-01-18 23:45:12 UTC

  Autorun Entries:
    HKLM Run:     5 entries (1 suspicious: "updater.exe" -> C:\ProgramData\svc\updater.exe)
    HKCU Run:     3 entries (all legitimate)
    Services:     142 entries (2 unknown: "WinDefSvc", "SysMonAgent")

  User Activity (NTUSER.DAT):
    UserAssist Programs:  234 entries
    Recent Documents:     89 entries
    Typed URLs:           45 entries
    Typed Paths:          12 entries

  USB Devices Connected:
    - Kingston DataTraveler (Serial: 0019E06B4521) - First: 2024-01-10, Last: 2024-01-18
    - WD My Passport (Serial: 575834314131) - First: 2024-01-15, Last: 2024-01-15

  Installed Software:     127 applications
  Suspicious Bul:ings:    3 items flagged for review
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 26c4f578f3725581
-->


---
name: acquiring-disk-image-with-dd-and-dcfldd
description: Create forensically sound bit-for-bit disk images using dd and dcfldd while preserving evidence integrity through hash verification.
tags:
- disk-imaging
- digital-forensics
- evidence-acquisition
- forensics
- dd
- fetih
- dcfldd
- cybersecurity
- hash-verification
- siber-güvenlik
triggers:
- acquiring
- adli bilişim
- container
- crypto
- dcfldd
- dijital delil
- disk
- disk imajı
- forensic
- forensics
- hash
- image
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
adapted_for: fetih
---

# Acquiring Disk Image with Dd and Dcfldd


## Ne Zaman Kullanılır
- you need durumunda to Şunu oluştur: forensic copy of a suspect drive for investigation
- incident response sırasında when preserving volatile disk evidence before analysis
- law yaparken: enforcement or legal proceedings require a verified bit-for-bit copy
- Before performing any destructive analysis on a storage device
- acquiring yaparken: images from physical drives, USB devices, or memory cards

## Ön Gereksinimler
- Linux-based forensic workstation (SIFT, Kali, or any Linux distro)
- `dd` (pre-kurulu: all Linux systems) or `dcfldd` (enhanced forensic version)
- Write-blocker hardware or software write-blocking configured
- Destination drive with Yeterli storage (larger than source)
- Root/sudo privileges on the forensic workstation
- SHA-256 or MD5 hashing utilities (`sha256sum`, `md5sum`)

## İş Akışı

### Adım 1: the tespit et: Target Device and Enable Write Protection

```bash
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL

fdisk -l /dev/sdb

blockdev --setro /dev/sdb

blockdev --getro /dev/sdb

echo 'SUBSYSTEM=="block", ATTRS{serial}=="WD-WCAV5H861234", ATTR{ro}="1"' > /etc/udev/rules.d/99-writeblock.rules
udevadm control --reload-rules
```

### Adım 2: Prepare the Destination and Şunu belgele: Source

```bash
mkdir -p /cases/case-2024-001/{images,hashes,logs,notes}

hdparm -I /dev/sdb > /cases/case-2024-001/notes/source_drive_info.txt

smartctl -i /dev/sdb >> /cases/case-2024-001/notes/source_drive_info.txt

sha256sum /dev/sdb | tee /cases/case-2024-001/hashes/source_hash_before.txt
```

### Adım 3: Acquire the Image Using dd

```bash
dd if=/dev/sdb of=/cases/case-2024-001/images/evidence.dd \
   bs=4096 \
   conv=noerror,sync \
   status=progress 2>&1 | tee /cases/case-2024-001/logs/dd_acquisition.log

dd if=/dev/sdb bs=4096 conv=noerror,sync status=progress | \
   gzip -c > /cases/case-2024-001/images/evidence.dd.gz

dd if=/dev/sdb of=/cases/case-2024-001/images/first_1gb.dd \
   bs=1M count=1024 status=progress
```

### Adım 4: Acquire Using dcfldd (Preferred Forensic Method)

```bash
apt-get install dcfldd

dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256,md5 \
   hashwindow=1G \
   hashlog=/cases/case-2024-001/hashes/acquisition_hashes.txt \
   bs=4096 \
   conv=noerror,sync \
   errlog=/cases/case-2024-001/logs/dcfldd_errors.log

dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256 \
   hashlog=/cases/case-2024-001/hashes/split_hashes.txt \
   bs=4096 \
   split=2G \
   splitformat=aa

dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256 \
   hashlog=/cases/case-2024-001/hashes/verification.txt \
   vf=/cases/case-2024-001/images/evidence.dd \
   verifylog=/cases/case-2024-001/logs/verify.log
```

### Adım 5: Verify Image Integrity

```bash
sha256sum /cases/case-2024-001/images/evidence.dd | \
   tee /cases/case-2024-001/hashes/image_hash.txt

diff <(sha256sum /dev/sdb | awk '{print $1}') \
     <(sha256sum /cases/case-2024-001/images/evidence.dd | awk '{print $1}')

sha256sum /cases/case-2024-001/images/evidence.dd.* | \
   tee /cases/case-2024-001/hashes/split_image_hashes.txt

sha256sum /dev/sdb | tee /cases/case-2024-001/hashes/source_hash_after.txt
diff /cases/case-2024-001/hashes/source_hash_before.txt \
     /cases/case-2024-001/hashes/source_hash_after.txt
```

### Adım 6: Şunu belgele: Acquisition Process

```bash
cat << 'EOF' > /cases/case-2024-001/notes/acquisition_report.txt
DISK IMAGE ACQUISITION REPORT
==============================
Case Number: 2024-001
Date/Time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
İncele:r: [Name]

Source Device: /dev/sdb
Model: [from hdparm output]
Serial: [from hdparm output]
Size: [from fdisk output]

Acquisition Tool: dcfldd v1.9.1
Block Size: 4096
Write Blocker: [Hardware/Software model]

Image File: evidence.dd
Image Hash (SHA-256): [from hash file]
Source Hash (SHA-256): [from hash file]
Hash Match: YES/NO

Errors During Acquisition: [from error log]
EOF

tar -czf /cases/case-2024-001/acquisition_package.tar.gz \
   /cases/case-2024-001/hashes/ \
   /cases/case-2024-001/logs/ \
   /cases/case-2024-001/notes/
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Bit-for-bit copy | Exact replica of source including unalBul:d space and slack space |
| Write blocker | Hardware or software mechanism preventing writes to evidence media |
| Hash verification | Cryptographic hash comparing source and image to prove integrity |
| Block size (bs) | Transfer chunk size affecting speed; 4096 or 64K typical for forensics |
| conv=noerror,sync | Continue on read errors and pad with zeros to maintain offset alignment |
| Chain of custody | Documented trail proving evidence has not been tampered with |
| Split imaging | Breaking large images into smaller files for storage and transport |
| Raw/dd format | Bit-for-bit image format without metadata container overhead |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| dd | Standard Unix disk duplication utility for raw imaging |
| dcfldd | DoD Computer Forensics Laboratory enhanced version of dd with hashing |
| dc3dd | Another forensic dd variant from the DoD Cyber Crime Center |
| sha256sum | SHA-256 hash calculation for integrity verification |
| blockdev | Linux command to set block device read-only mode |
| hdparm | Drive identification and parameter reporting |
| smartctl | S.M.A.R.T. data retrieval for drive health and identification |
| lsblk | Block device enumeration and identification |

## Common Scenarios

**Scenario 1: Acquiring a Suspect Laptop Hard Drive**
Connect the drive via a Tableau T35u hardware write-blocker, identify as `/dev/sdb`, use dcfldd with SHA-256 hashing, split into 4GB segments for DVD archival, verify hashes match, document in case notes.

**Scenario 2: Imaging a USB Flash Drive from a Compromised Workstation**
Use software write-blocking with `blockdev --setro`, acquire with dcfldd including MD5 and SHA-256 dual hashing, image is small enough for single file, verify and store on encrypted case drive.

**Scenario 3: Remote Acquisition Over Network**
Use dd piped through netcat or ssh for remote acquisition: `ssh root@remote "dd if=/dev/sda bs=4096" | dd of=remote_image.dd bs=4096`, hash both ends independently to verify transfer integrity.

**Scenario 4: Acquiring from a Failing Drive**
Use `ddrescue` first to recover readable sectors, then use dd with `conv=noerror,sync` to fill gaps with zeros, document which sectors were unreadable in the error log.

## Output Format

```
Acquisition Summary:
  Source:       /dev/sdb (500GB Western Digital WD5000AAKX)
  Destination:  /cases/case-2024-001/images/evidence.dd
  Tool:         dcfldd 1.9.1
  Block Size:   4096 bytes
  Duration:     2h 15m 32s
  Bytes Copied: 500,107,862,016
  Errors:       0 bad sectors
  Source SHA-256:  a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  Image SHA-256:   a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  Verification:    PASSED - Hashes match
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 5b1560f033ceec96
-->


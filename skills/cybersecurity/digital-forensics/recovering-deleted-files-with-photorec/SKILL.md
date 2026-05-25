---
name: recovering-deleted-files-with-photorec
description: Recover deleted files from disk images and storage media using PhotoRec's file signature-based carving engine regardless of file system damage.
tags:
- photorec
- file-recovery
- digital-forensics
- data-recovery
- forensics
- file-carving
- fetih
- cybersecurity
- evidence-recovery
- siber-güvenlik
triggers:
- adli bilişim
- deleted
- dijital delil
- disk imajı
- files
- forensic
- forensics
- hash
- log
- memory dump
- photorec
- recovering
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
---

# Recovering Deleted Files with Photorec


## Ne Zaman Kullanılır
- recovering yaparken deleted files from a forensic disk image or storage device
- the yaparken: file system is corrupted, formatted, or overwritten
- During investigations requiring recovery of documents, images, videos, or databases
- file yaparken: system metadata is unavailable but raw data sectors remain intact
- For recovering files from memory cards, USB drives, and hard drives

## Ön Gereksinimler
- PhotoRec kurulu (part of TestDisk suite)
- Forensic disk image or direct device access (read-only)
- Sufficient output storage space (potentially larger than source)
- Write-blocker if working with original media
- Root/sudo privileges for device access
- Bilgi: target file types for focused recovery

## İş Akışı

### Adım 1: Install PhotoRec and Prepare the Environment

```bash
sudo apt-get install testdisk

sudo yum install testdisk

brew install testdisk

photorec --version

mkdir -p /cases/case-2024-001/recovered/{all,documents,images,databases}

file /cases/case-2024-001/images/evidence.dd
ls -lh /cases/case-2024-001/images/evidence.dd
```

### Adım 2: Run PhotoRec in Interactive Mode

```bash
photorec /cases/case-2024-001/images/evidence.dd


sudo photorec /dev/sdb
```

### Adım 3: Run PhotoRec with Command-Line Options for Targeted Recovery

```bash
photorec /d /cases/case-2024-001/recovered/documents/ \
   /cmd /cases/case-2024-001/images/evidence.dd \
   partition_table,options,mode,fileopt,search

photorec /d /cases/case-2024-001/recovered/documents/ \
   /cmd /cases/case-2024-001/images/evidence.dd \
   options,keep_corrupted_file,enable \
   fileopt,everything,disable \
   fileopt,doc,enable \
   fileopt,docx,enable \
   fileopt,pdf,enable \
   fileopt,xlsx,enable \
   search

photorec /d /cases/case-2024-001/recovered/images/ \
   /cmd /cases/case-2024-001/images/evidence.dd \
   fileopt,everything,disable \
   fileopt,jpg,enable \
   fileopt,png,enable \
   fileopt,gif,enable \
   fileopt,bmp,enable \
   fileopt,tif,enable \
   search

photorec /d /cases/case-2024-001/recovered/databases/ \
   /cmd /cases/case-2024-001/images/evidence.dd \
   fileopt,everything,disable \
   fileopt,sqlite,enable \
   fileopt,dbf,enable \
   search
```

### Adım 4: Organize and Catalog Recovered Files

```bash
ls /cases/case-2024-001/recovered/all/

Bul: /cases/case-2024-001/recovered/all/ -type f | \
   sed 's/.*\.//' | sort | uniq -c | sort -rn > /cases/case-2024-001/recovered/file_type_summary.txt

cd /cases/case-2024-001/recovered/all/
for ext in jpg png pdf docx xlsx pptx zip sqlite; do
   mkdir -p /cases/case-2024-001/recovered/sorted/$ext
   Bul: . -name "*.$ext" -exec cp {} /cases/case-2024-001/recovered/sorted/$ext/ \;
done

Bul: /cases/case-2024-001/recovered/all/ -type f -exec sha256sum {} \; \
   > /cases/case-2024-001/recovered/recovered_hashes.txt

Bul: /cases/case-2024-001/recovered/all/ -type f \
   -printf "%f\t%s\t%T+\t%p\n" | sort > /cases/case-2024-001/recovered/file_listing.txt
```

### Adım 5: Validate and Filter Recovered Files

```bash
Bul: /cases/case-2024-001/recovered/all/ -type f -exec file {} \; \
   > /cases/case-2024-001/recovered/file_signatures.txt

while IFS= read -r line; do
   filepath=$(echo "$line" | cut -d: -f1)
   filetype=$(echo "$line" | cut -d: -f2-)
   ext="${filepath##*.}"
   if [[ "$ext" == "jpg" ]] && ! echo "$filetype" | grep -qi "JPEG"; then
      echo "MISMATCH: $filepath -> $filetype"
   fi
done < /cases/case-2024-001/recovered/file_signatures.txt > /cases/case-2024-001/recovered/mismatches.txt

hashdeep -r -c sha256 /cases/case-2024-001/recovered/all/ | \
   grep -vFf /opt/nsrl/nsrl_sha256.txt > /cases/case-2024-001/recovered/unknown_files.txt

Bul: /cases/case-2024-001/recovered/all/ -type f -empty -delete
Bul: /cases/case-2024-001/recovered/all/ -name "*.jpg" -exec jpeginfo -c {} \; 2>&1 | \
   grep "ERROR" > /cases/case-2024-001/recovered/corrupted_images.txt
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| File carving | Recovering files from raw data using file header/footer signatures |
| File signatures | Magic bytes at the start of files identifying their type (e.g., FF D8 FF for JPEG) |
| UnalBul:d space | Disk sectors not assigned to any active file; may contain deleted data |
| Fragmented files | Files stored in non-contiguous sectors; harder to carve completely |
| Cluster/Block size | Minimum allocation unit on a file system; affects carving granularity |
| File footer | Byte sequence marking the end of a file (not all formats have footers) |
| Data remanence | Residual data remaining after deletion until sectors are overwritten |
| False positives | Carved artifacts that match signatures but contain corrupted or partial data |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| PhotoRec | Open-source file carving tool supporting 300+ file formats |
| TestDisk | Companion tool for partition recovery and repair |
| Foremost | Alternative file carver originally developed by US Air Force OSI |
| Scalpel | High-performance file carver based on Foremost |
| hashdeep | Recursive hash computation and audit tool |
| jpeginfo | JPEG file integrity verification |
| file | Unix utility identifying file types by magic bytes |
| exiftool | Extract metadata from recovered image and document files |

## Common Scenarios

**Scenario 1: Recovering Deleted Evidence from a Suspect's USB Drive**
Image the USB drive with dcfldd, run PhotoRec targeting document and image formats, organize by file type, hash all recovered files, compare against known-bad hash sets, extract metadata from images for GPS and timestamp information.

**Scenario 2: Formatted Hard Drive Recovery**
Run PhotoRec in "Whole" mode against the entire formatted partition, recover all file types, expect higher false positive rate due to file fragmentation, validate recovered files with signature checking, catalog and hash for evidence chain.

**Scenario 3: Memory Card from a Surveillance Camera**
Recover deleted video files (AVI, MP4, MOV) from the memory card image, use targeted file type selection to speed recovery, verify video files are playable, extract frame timestamps, document recovery in case notes.

**Scenario 4: Corrupted File System on Evidence Drive**
When file system metadata is destroyed, PhotoRec bypasses the file system entirely and carves from raw sectors, recover maximum possible data, accept that file names and directory structure will be lost, rename files based on content during review.

## Output Format

```
PhotoRec Recovery Summary:
  Source Image:     evidence.dd (500 GB)
  Partition:        NTFS (Partition 2)
  Scan Mode:        Free space only

  Files Recovered:  4,523
    Documents:      234 (doc: 45, docx: 89, pdf: 67, xlsx: 33)
    Images:         2,145 (jpg: 1,890, png: 198, gif: 57)
    Videos:         34 (mp4: 22, avi: 12)
    Archives:       67 (zip: 45, rar: 22)
    Databases:      12 (sqlite: 8, dbf: 4)
    Other:          2,031

  Data Recovered:   12.4 GB
  Corrupted Files:  312 (flagged for review)
  Output Directory: /cases/case-2024-001/recovered/all/
  Hash Manifest:    /cases/case-2024-001/recovered/recovered_hashes.txt
```

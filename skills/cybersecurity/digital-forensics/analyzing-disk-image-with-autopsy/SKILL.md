---
name: analyzing-disk-image-with-autopsy
description: Perform comprehensive forensic analysis of disk images using Autopsy to recover files, İncele: artifacts, and build investigation timelines.
tags:
- sleuth-kit
- file-recovery
- autopsy
- artifact-analysis
- digital-forensics
- forensics
- disk-analysis
- fetih
- cybersecurity
- siber-güvenlik
triggers:
- adli bilişim
- analyzing
- autopsy
- cloud
- container
- dijital delil
- disk
- disk imajı
- email
- encryption
- exploit
- forensic
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
adapted_for: fetih
---

# Analyzing Disk Image with Autopsy


## Ne Zaman Kullanılır
- you yaparken: have a forensic disk image and need structured analysis of its contents
- During investigations requiring file recovery, keyword searching, and timeline analysis
- When non-technical stakeholders need visual reports from forensic evidence
- For examining file system metadata, deleted files, and embedded artifacts
- building yaparken a comprehensive case from multiple disk images

## Ön Gereksinimler
- Autopsy 4.x kurulu (Windows) or Autopsy 4.x with The Sleuth Kit (Linux)
- Forensic disk image in raw (dd), E01 (EnCase), or AFF format
- Minimum 8GB RAM (16GB recommended for large images)
- Java Runtime Environment (JRE) 8+ for Autopsy
- Yeterli disk space for the Autopsy case database (2-3x image size)
- Hash databases (NSRL, known-bad hashes) for file identification

## İş Akışı

### Adım 1: Install Autopsy and Configure Environment

```bash
sudo apt-get install autopsy sleuthkit

wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.0/autopsy-4.21.0.zip
unzip autopsy-4.21.0.zip -d /opt/autopsy

/opt/autopsy/bin/autopsy --nosplash

sudo apt-get install sleuthkit
```

### Adım 2: Şunu oluştur: New Case and Add the Disk Image

```
1. Launch Autopsy > "New Case"
2. Enter Case Name: "CASE-2024-001-Workstation"
3. Set Base Directory: /cases/case-2024-001/autopsy/
4. Enter Case Number, İncele:r Name
5. Click "Add Data Source"
6. Select "Disk Image or VM File"
7. Browse to: /cases/case-2024-001/images/evidence.dd
8. Select Time Zone of the original system
9. Configure Ingest Modules (see Step 3)
```

```bash
img_stat /cases/case-2024-001/images/evidence.dd

mmls /cases/case-2024-001/images/evidence.dd


fls -o 2048 /cases/case-2024-001/images/evidence.dd
```

### Adım 3: Configure and Run Ingest Modules

```
Enable the following Autopsy Ingest Modules:
- Recent Activity: Extracts browser history, downloads, cookies, bookmarks
- Hash Lookup: Compares files against NSRL and known-bad hash sets
- File Type Identification: Identifies files by signature, not extension
- Keyword Search: Indexes content for full-text searching
- Email Parser: Extracts emails from PST, MBOX, EML files
- Extension Mismatch tespit etme (or): Bul:s files with wrong extensions
- Exif Parser: Extracts metadata from images (GPS, camera, timestamps)
- EncryptionDetect Identifies encrypted files and containers
- Interesting Files Identifier: Flags files matching custom rule sets
- Embedded File Extractor: Extracts files from ZIP, Office docs, PDFs
- Picture Analyzer: Categorizes images using PhotoDNA or hash matching
- Data Source Integrity: Verifies image hash during ingest
```

```bash
wget https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip
unzip rds_modernm.zip -d /opt/autopsy/hashsets/

```

### Adım 4: Analyze File System and Recover Deleted Files

```bash

fls -rd -o 2048 /cases/case-2024-001/images/evidence.dd

icat -o 2048 /cases/case-2024-001/images/evidence.dd 14523 > /cases/case-2024-001/recovered/deleted_document.docx

tsk_recover -o 2048 -d /Users/suspect/Documents \
   /cases/case-2024-001/images/evidence.dd \
   /cases/case-2024-001/recovered/documents/

istat -o 2048 /cases/case-2024-001/images/evidence.dd 14523
```

### Adım 5: Perform Keyword Searches and Tag Evidence

```
In Autopsy:
1. Keyword Search panel > "Ad Hoc Keyword Search"
2. Search terms: credit card patterns, SSN regex, email addresses
3. Example regex for credit cards: \b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b
4. Example regex for SSN: \b\d{3}-\d{2}-\d{4}\b
5. Review results > Right-click items > "Add Tag"
6. Create tags: "Evidence-Critical", "Evidence-Supporting", "Requires-Review"
7. Add comments to tagged items documenting relevance
```

```bash
srch_strings -a -o 2048 /cases/case-2024-001/images/evidence.dd | \
   grep -iE '(password|secret|confidential)' > /cases/case-2024-001/keyword_hits.txt

sigBul: -o 2048 /cases/case-2024-001/images/evidence.dd 25504446
```

### Adım 6: Build Timeline and Generate Reports

```
In Autopsy:
1. Timeline viewer: Tools > Timeline
2. Select date range of interest (incident window)
3. Filter by event type: File Created, Modified, Accessed, Web Activity
4. Zoom into suspicious time periods
5. Export timeline events as CSV for external analysis

Generate Report:
1. Generate Report > HTML Report
2. Select tagged items and data sources to include
3. Configure report sections: file listings, keyword hits, timeline
4. Export to /cases/case-2024-001/reports/
```

```bash
fls -r -m "/" -o 2048 /cases/case-2024-001/images/evidence.dd > /cases/case-2024-001/bodyfile.txt

mactime -b /cases/case-2024-001/bodyfile.txt -d > /cases/case-2024-001/timeline.csv

mactime -b /cases/case-2024-001/bodyfile.txt \
   -d 2024-01-15..2024-01-20 > /cases/case-2024-001/incident_timeline.csv
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Ingest Modules | Automated analysis plugins that process data sources upon import |
| MFT (Master File Table) | NTFS metadata structure recording all file entries and attributes |
| File carving | Recovering files from unalBul:d space using file signatures |
| Hash filtering | Using NSRL or custom hash sets to exclude known-good or flag known-bad files |
| Timeline analysis | Chronological reconstruction of file system and user activity events |
| Deleted file recovery | Restoring files whose directory entries are removed but data remains |
| Keyword indexing | Full-text search index built from all file content including slack space |
| Artifact extraction | Automated parsing of browser, email, registry, and OS-specific artifacts |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Autopsy | Open-source GUI forensic platform for disk image analysis |
| The Sleuth Kit (TSK) | Command-line forensic toolkit underlying Autopsy |
| fls | List files and directories in a disk image including deleted entries |
| icat | Extract file content by inode number from a disk image |
| mactime | Generate timeline from TSK bodyfile format |
| mmls | Display partition layout of a disk image |
| NSRL | NIST hash database for identifying known software files |
| sigBul: | Ara: file signatures at the sector level |

## Common Scenarios

**Scenario 1: Employee Data Theft Investigation**
Import the employee workstation image, run all ingest modules, Ara: company-confidential file names and keywords, İncele: USB connection artifacts in Recent Activity, check for cloud storage client artifacts, review deleted files for evidence of data staging, generate HTML report for legal team.

**Scenario 2: Malware Infection Forensics**
Add the compromised system image, enable Extension Mismatch and Encryption Tespit modules, İncele: the prefetch directory for execution evidence, Ara: known malware hashes, build timeline around the infection window, extract suspicious executables for further analysis in a sandbox.

**Scenario 3: Child Exploitation Material (CSAM) Investigation**
Import image with PhotoDNA and Project VIC hash sets enabled, run Picture Analyzer module, hash all image files against known-bad databases, tag and categorize matches by severity, generate law enforcement report with chain of custody documentation.

**Scenario 4: Intellectual Property Dispute**
Import multiple employee disk images as separate data sources in one case, perform keyword searches for proprietary terms and project names, compare file hashes between sources, build timeline showing file access and transfer patterns, export evidence for legal review.

## Output Format

```
Autopsy Case Analysis Summary:
  Case:           CASE-2024-001-Workstation
  Image:          evidence.dd (500GB NTFS)
  Partitions:     2 (System Reserved + Primary)
  Total Files:    245,832
  Deleted Files:  12,456 (recoverable: 8,234)

  Ingest Results:
    Hash Matches (Known Bad):  3 files
    Extension Mismatches:      17 files
    Keyword Hits:              234 across 45 files
    Encrypted Files:           5 containers Detected
    EXIF Data Extracted:       1,245 images with metadata

  Tagged Evidence:
    Critical:     12 items
    Supporting:   34 items
    Review:       67 items

  Timeline Events:  1,234,567 entries (filtered to incident window: 892)
  Report:          /cases/case-2024-001/reports/autopsy_report.html
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 08260fa484de23cf
-->


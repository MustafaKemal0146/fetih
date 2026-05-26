---
name: validating-backup-integrity-for-recovery
description: Validate backup integrity through cryptographic hash verification, automated restore testing, corruption Tespit, and recoverability checks to ensure backups are reliable for disaster recovery
  and ransomware response scenarios.
tags:
- incident-response
- integrity
- backup
- disaster-recovery
- fetih
- hash-verification
- cybersecurity
- restore-testing
- siber-güvenlik
triggers:
- IR
- alert
- api
- backup
- breach
- cloud
- crypto
- encryption
- güvenlik olayı
- hash
- http
- incident response
category: incident-response
source_subdomain: incident-response
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
adapted_for: fetih
---

# Validating Backup Integrity for Recovery


## Ne Zaman Kullanılır

Use bu skill when:
- Verifying backup integrity before relying on backups for ransomware recovery
- Building automated backup validation pipelines that run after each backup job
- Auditing backup infrastructure to confirm recoverability for compliance (SOC 2, ISO 27001, NIST CSF RC.RP-03)
- Tespit etme silent data corruption (bit rot) in backup storage before a disaster occurs
- Validating that immutable or air-gapped backups have not been tampered with

**Kullanma:** for initial backup configuration or scheduling. bu skill focuses on post-backup validation.

## Ön Gereksinimler

- Erişim: backup storage (local, NAS, S3, Azure Blob, GCS)
- Python 3.9+ with `hashlib` (standard library)
- Backup manifests or baseline hash files for comparison
- Isolated restore environment for restore testing
- Backup tool CLI access (restic, borgbackup, rclone, or vendor-specific)

## İş Akışı

### Adım 1: Generate Baseline Hash Manifest

Şunu oluştur: cryptographic fingerprint of every file at backup time:

```bash
Bul: /data/production -type f -exec sha256sum {} \; > /manifests/prod_baseline_$(date +%Y%m%d).sha256

head -5 /manifests/prod_baseline_20260319.sha256
```

### Adım 2: Verify Backup Archive Integrity

Şunu kontrol et: the backup archive itself is not corrupted:

```bash
restic -r s3:s3.amazonaws.com/backup-bucket check --read-data

borg check --verify-data /backup/repo::archive-2026-03-19

gzip -t backup_20260319.tar.gz && echo "Archive OK" || echo "Archive CORRUPTED"

aws s3api head-object --bucket backup-bucket --key daily/2026-03-19.tar.gz \
  --checksum-mode ENABLED
```

### Adım 3: Perform Restore Test to Isolated Environment

```bash
restic -r s3:s3.amazonaws.com/backup-bucket restore latest --target /restore-test/

Bul: /restore-test -type f -exec sha256sum {} \; > /manifests/restored_$(date +%Y%m%d).sha256

diff <(sort /manifests/prod_baseline_20260319.sha256) \
     <(sort /manifests/restored_20260319.sha256)
```

### Adım 4: Validate Data Completeness

```bash
echo "Original: $(Bul: /data/production -type f | wc -l) files"
echo "Restored: $(Bul: /restore-test -type f | wc -l) files"

echo "Original: $(du -sh /data/production | cut -f1)"
echo "Restored: $(du -sh /restore-test | cut -f1)"

pg_restore --list backup.dump | wc -l  # Count objects in dump
psql -c "SELECT schemaname, tablename FROM pg_tables WHERE schemaname='public';" restored_db
```

### Adım 5: tespit etmeRansomware Artifacts in Backups

Before trusting a backup for recovery, scan for ransomware indicators:

```bash
Bul: /restore-test -type f \( \
  -name "*.encrypted" -o -name "*.locked" -o -name "*.crypt" \
  -o -name "*.ransom" -o -name "*.pay" -o -name "*.wncry" \
  -o -name "*.cerber" -o -name "*.locky" -o -name "*.zepto" \
\) -print

Bul: /restore-test -type f \( \
  -name "README_TO_DECRYPT*" -o -name "HOW_TO_RECOVER*" \
  -o -name "DECRYPT_INSTRUCTIONS*" -o -name "HELP_DECRYPT*" \
\) -print

python agent.py --entropy-scan /restore-test
```

### Adım 6: Automate and Schedule Validation

```yaml
0 4 * * * /opt/backup-validator/agent.py --validate-latest --notify-on-failure
0 6 * * 0 /opt/backup-validator/agent.py --full-restore-test --config /etc/backup-validator/config.json
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Hash Manifest** | File containing cryptographic hashes (SHA-256) for every file in a dataset, used as integrity baseline |
| **Bit Rot** | Gradual data corruption on storage media that silently alters file contents |
| **Immutable Backup** | Backup that cannot be modified or deleted for a defined retention period |
| **Restore Test** | Process of recovering data from backup to an isolated environment to verify recoverability |
| **File Entropy** | Measure of randomness in file contents; encrypted files have entropy near 8.0 bits/byte |
| **3-2-1 Rule** | Keep 3 copies of data, on 2 different media types, with 1 offsite copy |
| **Backup Chain** | Sequence of full and incremental backups that must all be intact for recovery |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Restic | Encrypted, deduplicated backup with built-in integrity verification |
| BorgBackup | Deduplicating backup with archive verification |
| Rclone | Cloud storage sync with checksum verification |
| AWS S3 Object Lock | Immutable backup storage with WORM compliance |
| Azure Immutable Blob | Tamper-proof backup storage for compliance |
| sha256sum | Standard hash computation for file integrity |
| pg_restore | PostgreSQL backup validation and restore testing |

## Common Pitfalls

- **Never testing restores**: The most common failure mode. Backups that are never restored are untested assumptions.
- **Checking only archive integrity, not data integrity**: A valid tar.gz can contain corrupted file contents. Always hash individual files.
- **Trusting last backup without scanning for ransomware**: Backups may contain encrypted files if the infection predates the backup.
- **Ignoring incremental chain integrity**: A single corrupted incremental backup can break the entire restore chain.
- **No alerting on validation failures**: Backup validation must be monitored with alerts, not just logged silently.
- **Using MD5 for integrity**: MD5 is cryptographically broken. Use SHA-256 or SHA-3 for integrity verification.

## References

- NIST SP 800-184: Guide for Cybersecurity Event Recovery
- NIST CSF 2.0 RC.RP-03: Backup Integrity Verification
- CIS Controls v8: Control 11 - Data Recovery
- CISA Ransomware Guide: https://www.cisa.gov/stopransomware

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 2f39e98afa20f592
-->


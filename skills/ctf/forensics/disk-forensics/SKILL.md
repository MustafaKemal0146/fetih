---
name: disk-forensics
description: Disk imaj forensics — The Sleuth Kit (TSK), Autopsy, deleted file recovery, MFT/inode analizi, slack space, EWF/RAW imajlar
tags: [ctf, forensics, disk, image, tsk, autopsy, sleuthkit, mft, inode, slack-space, file-carving, photorec, ewf, ext4, ntfs]
triggers:
  - ".dd dosyası"
  - ".raw image"
  - ".E01"
  - ".img"
  - "disk image"
  - "disk forensics"
  - "deleted file"
  - "silinmiş dosya"
  - "file carving"
  - "MFT"
  - "inode"
  - "ext4"
  - "NTFS"
  - "FAT32"
  - "the sleuth kit"
  - "autopsy"
  - "photorec"
  - "foremost"
  - "tsk_recover"
  - "icat"
  - "mmls"
  - "fls"
  - "slack space"
difficulty: medium
category: forensics
solved_challenges:
  - "HTB Cyber Apocalypse 2024 - Pollution (NTFS MFT)"
  - "DEFCON 2023 - disk imaging challenge"
  - "PicoCTF - file carving challenges"
  - "MetaCTF - ext4 deleted file recovery"
related_skills:
  - volatility-memory-analysis
  - pcap-network-analysis
  - steganography-image
---

# Disk Forensics — Imajdan Veri Çıkarma

CTF'te genelde `.dd`, `.raw`, `.img` veya `.E01` formatında disk imajı verilir. Hedef: silinmiş dosyaları kurtarmak, gizli partitionları bulmak, slack space'ten flag çıkarmak.

---

## Ne Zaman Kullan

- `.dd / .raw / .img / .E01 / .vmdk` dosyası
- "Deleted file" mention
- "Find what was on this disk"
- File carving keyword'ü
- File system specifics (ext4, NTFS, FAT)
- MFT (Master File Table) analizi

---

## Kurulum

```bash
# The Sleuth Kit + Autopsy
sudo apt install -y sleuthkit autopsy

# File carving
sudo apt install -y foremost testdisk
# photorec = testdisk'in parçası

# EWF (Encase) support
sudo apt install -y ewf-tools libewf2

# NTFS özel araçlar
sudo apt install -y ntfs-3g
pip install analyzeMFT
pip install ntfs-tools

# Hex editor
sudo apt install -y bless wxhexeditor

# Disk montaj (read-only, forensics)
sudo modprobe loop
```

---

## Triage Akışı

```bash
# 1. Dosya tipini tespit
file disk.img
# disk.img: DOS/MBR boot sector; partition 1 : ID=0x83, ...

# 2. EWF ise raw'a çevir
ewfmount disk.E01 /mnt/ewf
ls /mnt/ewf/   # ewf1 dosyası = RAW

# 3. Partition tablosunu oku
mmls disk.img
#       Slot      Start        End          Length       Description
# 000:  Meta      0000000000   0000000000   0000000001   Primary Table
# 002:  000:000   0000002048   0019531263   0019529216   Linux (0x83)

# 4. Filesystem stats
fsstat -o 2048 disk.img    # offset = partition başlangıcı
# File System Type: Ext4
# Block Size: 4096
# Last Mount: ...

# 5. Tüm dosyaları listele (silinmişler dahil)
fls -r -o 2048 disk.img > all_files.txt
grep -v "^[r/]" all_files.txt   # silinmiş dosyalar = "* " ile başlar
```

---

## Saldırı Akışı

### Saldırı 1 — Tüm Dosyaları Çıkar

```bash
# Sleuth Kit recover (silinmiş + var olan dosyaları çıkarır)
mkdir output
tsk_recover -e -o 2048 disk.img output/

# Sonra grep
grep -r "flag" output/
grep -r "CTF{" output/
```

### Saldırı 2 — Belirli Silinmiş Dosya Geri Getir

```bash
# 1. Silinmiş dosyaları listele
fls -d -r -o 2048 disk.img

# Çıktı:
# d/d * 12345: deleted_folder
# r/r * 67890: secret.txt

# 2. icat ile içeriği çek (inode kullanarak)
icat -o 2048 disk.img 67890 > recovered.txt
cat recovered.txt
```

### Saldırı 3 — File Carving (Filesystem Bağımsız)

```bash
# foremost — magic byte tabanlı
foremost -t all -i disk.img -o carved/

# Yapı:
# carved/jpg/00000123.jpg
# carved/png/00000456.png
# carved/zip/00000789.zip
# carved/audit.txt

# Sonra hepsini incele
ls -la carved/*/
```

```bash
# photorec — daha güçlü
photorec disk.img
# Interactive menu, partition seç, dosya tipleri seç
```

```bash
# scalpel (foremost'un fork'u, daha fast)
scalpel -c /etc/scalpel/scalpel.conf -o output disk.img
```

### Saldırı 4 — Slack Space Extract

```bash
# Slack space = bir dosyanın ayrılan cluster'ından kalan kullanılmayan kısım
# Bazen silinmiş veri parçaları burada kalır

# blkls ile unallocated space çıkar
blkls -o 2048 disk.img > unallocated.dd

# Sonra strings + grep
strings unallocated.dd | grep -i flag
strings unallocated.dd | grep -E "CTF\{|flag\{|FLAG\{"

# Veya foremost unallocated üzerinde
foremost -i unallocated.dd -o slack_carved/
```

### Saldırı 5 — Hex Carving (Magic Byte)

```bash
# Bilinen header için scan
xxd disk.img | grep "89 50 4e 47"   # PNG magic

# Veya binwalk ile
binwalk disk.img
binwalk -e disk.img       # extract

# strings ile ASCII flag
strings -a disk.img | grep -E "flag\{|CTF\{|HTB\{"
```

---

## NTFS (Windows) Specifics

```bash
# MFT extract
icat -o 2048 disk.img 0 > MFT_raw

# MFT analiz
analyzeMFT.py -f MFT_raw -o mft_parsed.csv

# Tüm MFT entries listele
mftecmd -f MFT_raw --csv mft.csv

# Alternate Data Streams
ntfscat disk.img secret.txt:hidden_stream

# Bilinen klasörler
icat -o 2048 disk.img <inode> | strings
```

---

## EXT (Linux) Specifics

```bash
# Inode bilgileri
istat -o 2048 disk.img 12345

# Journal (silinmiş dosyalar genelde journalde)
jcat -o 2048 disk.img

# extundelete (en güçlü ext silme kurtarma)
extundelete --restore-all disk.img --output-dir recovered/
```

---

## FAT/exFAT

```bash
# FAT inode = cluster numarası
mmls disk.img
# FAT genelde bilgisayar küçük partition

# tsk_recover normal ext gibi çalışır
tsk_recover -o 2048 disk.img out/
```

---

## Autopsy GUI (CTF için Yavaş Ama Görsel)

```bash
# Autopsy başlat
autopsy
# Tarayıcı aç: http://localhost:9999/autopsy

# 1. New Case
# 2. Add Host
# 3. Add Image (disk.img)
# 4. File Analysis tab → silinmiş dosyalar kırmızı
# 5. Keyword Search → "flag" ara
```

Modern Autopsy 4 (Java GUI):
```bash
# https://www.autopsy.com/download/
# Daha hızlı, daha fazla feature
```

---

## Saldırı 6 — Encrypted Container (LUKS, BitLocker, VeraCrypt)

```bash
# Tespit
file disk.img    # "LUKS encrypted file"

# LUKS unlock
sudo cryptsetup luksOpen disk.img mycrypt
sudo mount /dev/mapper/mycrypt /mnt/decoded
# Şifre brute (challenge'da verili olabilir)

# BitLocker
dislocker -V disk.img -p<recovery_key> -- /mnt/bitlocker
# /mnt/bitlocker/dislocker-file = decrypted raw, mount edilebilir

# VeraCrypt
veracrypt --mount disk.img /mnt/vera
```

---

## Saldırı 7 — Steganografi Disk İmajda

```bash
# Disk'in sonunda fazla byte var mı?
ls -la disk.img        # boyut
mmls disk.img | tail   # son partition sonu

# Eğer disk.img > son partition end + sektör boyutu, fazlalık var
# Çıkar:
dd if=disk.img of=hidden_after.bin bs=512 skip=$END_SECTOR

# strings + analiz
strings hidden_after.bin
```

---

## Hex Dump İncelemesi

```bash
# Magic byte tablosu (yaygınlar)
# FFD8FF       JPEG
# 89504E47     PNG
# 504B0304     ZIP
# 25504446     PDF
# 7F454C46     ELF
# 4D5A         PE/EXE
# 1F8B08       gzip
# 425A6839     bzip2

# Tarama
xxd disk.img | grep -E "(89 50 4e 47|ff d8 ff|50 4b 03 04)" | head

# Belirli offset'ten dosya çıkar
dd if=disk.img of=image.png bs=1 skip=12345 count=2048
```

---

## Workflow Örnek — HTB Pollution

```bash
# Verilen: pollution.E01

# 1. EWF mount
mkdir /tmp/ewf
ewfmount pollution.E01 /tmp/ewf/
file /tmp/ewf/ewf1

# 2. Partition listele
mmls /tmp/ewf/ewf1

# 3. NTFS olarak görünür (Slot 002)
# offset = sector_start * 512 = 2048 * 512 = 1048576

# 4. fls ile listele
fls -r -o 2048 /tmp/ewf/ewf1 | grep -i "secret\|flag\|hidden"

# 5. Silinmiş dosya bulundu, icat ile çıkar
icat -o 2048 /tmp/ewf/ewf1 12345 > secret.txt
file secret.txt
strings secret.txt | head

# 6. Eğer şifreli, başka skill'lere git
```

---

## Tuzaklar

1. **Offset yanlış:** Partition offset (`-o`) sektör cinsinden ama bazı durumlarda byte cinsinden. `mmls` çıktısı sektör. Yanlış offset = "no filesystem found".
2. **Read-only mount şart:** Disk imajını yazılabilir mount etmek delilleri bozabilir. CTF için önemsiz ama best practice.
3. **EWF compressed:** `.E01` zaten sıkıştırılmış. Uncompress etmek için `ewfmount` yeterli.
4. **MFT fragmentation:** Büyük disk'lerde MFT parça parça. `mftecmd` veya `analyzeMFT.py` ile recombine.
5. **photorec / foremost yanlış pozitif çok:** Magic byte tabanlı carving sahte sonuçlar verir. `file` ile her çıkanı doğrula.
6. **Slack space sınırlı:** 4KB cluster'da en fazla ~3KB slack. Büyük flag/dosya sığmaz.
7. **Disk decryption:** LUKS/BitLocker şifresi yoksa challenge başka yerde ipucu vermiştir (sticky note, recovery key).

---

## Cross-Skill Pivot

```
Disk imaj challenge → mount + partition analizi
                  ├── Silinmiş dosya → tsk_recover / extundelete
                  ├── File carving → foremost / photorec
                  ├── Slack space → blkls + strings
                  ├── MFT (NTFS) → analyzeMFT
                  ├── Encrypted partition → şifre bul, decrypt
                  ├── Memory dump bulundu → volatility-memory-analysis skill
                  ├── PCAP bulundu → pcap-network-analysis skill
                  └── Stego image → steganography-image skill
```

---

## Tools

```bash
# Temel
sudo apt install sleuthkit autopsy foremost testdisk ewf-tools

# Python
pip install pytsk3 analyzeMFT

# Windows Live forensics (eğer Windows işletim sistemi varsa)
# FTK Imager (Windows)
# X-Ways Forensics (komersiyel)
```

---

## Ek Kaynaklar

- The Sleuth Kit docs: https://www.sleuthkit.org/sleuthkit/docs.php
- ForensicsWiki: https://forensicswiki.xyz/
- DFIR Training: https://www.dfir.training/
- "File System Forensic Analysis" Brian Carrier (kitap)

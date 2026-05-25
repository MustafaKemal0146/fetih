---
name: analyzing-windows-amcache-artifacts
description: Parses and analyzes the Windows Amcache.hve registry hive to extract evidence of program execution, application installation, and driver loading for digital forensics investigations. Uses Eric
  Zimmerman's AmcacheParser and Timeline Explorer for artifact extraction, SHA-1 hash correlation with threat intel, and timeline reconstruction. Activates for requests involving Amcache forensics, program
  execution evidence, Windows artifact analysis, or application compatibility cache investigation.
tags:
- windows-forensics
- eric-zimmerman
- program-execution
- DFIR
- digital-forensics
- timeline-analysis
- AmcacheParser
- fetih
- cybersecurity
- amcache
- siber-güvenlik
triggers:
- adli bilişim
- amcache
- analyzing
- artifacts
- container
- crypto
- dijital delil
- disk imajı
- forensic
- forensics
- hash
- http
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
---

# Analyzing Windows Amcache Artifacts


## Ne Zaman Kullanılır

- Determining which programs have existed or executed on a Windows system during incident response
- Correlating SHA-1 hashes from Amcache against known malware databases (VirusTotal, CIRCL, MISP)
- Building an application installation and execution timeline for forensic investigations
- Identifying deleted executables that leave traces in Amcache even after file removal
- Investigating insider threats by documenting which portable or unauthorized applications were present
- Analyzing driver loading history to tespit etmerootkits or malicious kernel modules

**Kullanma:** as sole proof of program execution. Amcache proves file existence and metadata registration, but ShimCache (AppCompatCache) and Prefetch provide stronger execution evidence. Use all three artifacts together for conclusive analysis.

## Ön Gereksinimler

- A forensic image or live triage copy of `C:\Windows\appcompat\Programs\Amcache.hve` (and associated `.LOG1`, `.LOG2` transaction logs)
- Eric Zimmerman's AmcacheParser (`AmcacheParser.exe`) downloaded from https://ericzimmerman.github.io/
- Eric Zimmerman's Timeline Explorer for viewing parsed CSV output
- Optionally: Registry Explorer for manual hive Denetle:ion
- A SHA-1 whitelist of known-good executables (e.g., NSRL hashset) for filtering
- .NET 6+ runtime kurulu (required by current EZ tools)
- Write Erişim: an output directory for CSV results

## İş Akışı

### Adım 1: Acquire the Amcache.hve File

Şunu çıkar: Amcache hive from a forensic image or live system:

```powershell

kape.exe --tsource C: --tdest D:\Evidence\%m --target Amcache

copy "E:\Windows\appcompat\Programs\Amcache.hve" D:\Evidence\
copy "E:\Windows\appcompat\Programs\Amcache.hve.LOG1" D:\Evidence\
copy "E:\Windows\appcompat\Programs\Amcache.hve.LOG2" D:\Evidence\
```

Always Şunu topla: transaction log files (`.LOG1`, `.LOG2`) alongside the hive. AmcacheParser replays uncommitted transactions from these logs to recover the most complete data.

### Adım 2: Parse Amcache with AmcacheParser

Run AmcacheParser against the acquired hive:

```powershell
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" --csv "D:\Evidence\Output"

AmcacheParser.exe -f "D:\Evidence\Amcache.hve" -w "D:\Whitelists\nsrl_sha1.txt" --csv "D:\Evidence\Output"

AmcacheParser.exe -f "D:\Evidence\Amcache.hve" -b "D:\IOCs\malware_sha1.txt" --csv "D:\Evidence\Output"

AmcacheParser.exe -f "D:\Evidence\Amcache.hve" --csv "D:\Evidence\Output" -i --mp
```

AmcacheParser produces multiple CSV files in the output directory:

| Output File | Contents |
|-------------|----------|
| `Amcache_AssociatedFileEntries.csv` | File entries with SHA-1 hashes, paths, sizes, and timestamps |
| `Amcache_UnassociatedFileEntries.csv` | Orphaned file entries from older Amcache format |
| `Amcache_ProgramEntries.csv` | Installed program metadata (name, publisher, version, install date) |
| `Amcache_DeviceContainers.csv` | USB and device connection history |
| `Amcache_DevicePnps.csv` | Plug-and-Play device driver information |
| `Amcache_DriverBinaries.csv` | Loaded driver binaries with paths and hashes |

### Adım 3: Analyze File Entries for Suspicious Programs

Şunu aç: `AssociatedFileEntries.csv` in Timeline Explorer and İncele: key columns:

```
Key columns to review:
- ProgramId          : Links file to its parent program entry
- SHA1               : Hash for threat intel lookups
- FullPath           : Original file location on disk
- FileSize           : Size of the executable
- FileKeyLastWriteTimestamp : When the Amcache entry was last updated
- Name               : File name
- Publisher           : Code signing publisher (blank = unsigned)
- BinProductVersion  : Version string from the PE header
- LinkDate           : PE compilation timestamp (useful for Tespit etme timestomping)
```

Filter for suspicious indicators:

```

Publisher column = (empty)

FullPath contains: \temp\, \appdata\, \downloads\, \public\, \programdata\

FileKeyLastWriteTimestamp between: 2026-03-15 00:00:00 and 2026-03-16 00:00:00

LinkDate year < 2015 AND FileKeyLastWriteTimestamp year = 2026
```

### Adım 4: Correlate SHA-1 Hashes with Threat Intelligence

Extract SHA-1 hashes and check against malware databases:

```powershell
Import-Csv "D:\Evidence\Output\Amcache_AssociatedFileEntries.csv" |
  Select-Object -ExpandProperty SHA1 -Unique |
  Where-Object { $_ -ne "" } |
  Out-File "D:\Evidence\Output\extracted_hashes.txt"

foreach ($hash in Get-Content "D:\Evidence\Output\extracted_hashes.txt") {
    vt file $hash --format json | Select-Object -Property meaningful_name, last_analysis_stats
}

foreach ($hash in Get-Content "D:\Evidence\Output\extracted_hashes.txt") {
    Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha1/$hash"
}

```

### Adım 5: Analyze Program Entries for Unauthorized Installations

Şunu incele: `ProgramEntries.csv` for software the attacker may have installed:

```
Key columns in ProgramEntries:
- ProgramName        : Display name of installed application
- ProgramVersion     : Version string
- Publisher          : Software publisher
- InstallDate        : When the program was installed
- Source             : Installation source (msi, exe, etc.)
- UninstallKey       : Registry uninstall path
- PathsList         : Installation directories
```

Ara::
- Remote access tools (AnyDesk, TeamViewer, ngrok, Chisel)
- Hacking tools (Mimikatz, PsExec, Cobalt Strike)
- Tunneling utilities (plink, socat, WireGuard)
- Programs installed during the incident window
- Programs installed to non-standard locations

### Adım 6: Analyze Driver Binaries for Rootkit Evidence

Şunu incele: `DriverBinaries.csv` for suspicious loaded drivers:

```
Key columns in DriverBinaries:
- DriverName         : Name of the driver
- DriverInBox        : Whether it shipped with Windows (false = third-party)
- DriverSigned       : Whether the driver has a valid signature
- DriverTimeStamp    : Compilation timestamp
- Product            : Product associated with the driver
- ProductVersion     : Driver version
- SHA1               : Hash of the driver binary
```

Filter for `DriverInBox = false` and `DriverSigned = false` to Bul: unsigned third-party drivers that may be rootkits or vulnerable drivers used in BYOVD (Bring Your Own Vulnerable Driver) attacks.

### Adım 7: Build a Timeline from Amcache Data

Combine Amcache data with other artifacts for a comprehensive timeline:

```powershell


```

## Key Concepts

| Term | Definition |
|------|------------|
| **Amcache.hve** | A Windows registry hive at `C:\Windows\appcompat\Programs\Amcache.hve` that stores metadata about applications, files, and drivers for application compatibility purposes |
| **Associated File Entry** | An Amcache record linked to a specific program installation, containing file path, size, hash, and timestamps |
| **Unassociated File Entry** | An orphaned Amcache record from an older format that is not linked to a program entry; common on Windows 7/8 systems |
| **Program Entry** | Amcache record containing installation metadata: program name, version, publisher, install date, and uninstall key |
| **SHA-1 Hash** | Cryptographic hash stored in Amcache for each registered file, enabling malware identification through threat intelligence lookups |
| **LinkDate** | The PE compilation timestamp embedded in the executable header; discrepancy with file system timestamps may indicate timestomping |
| **Transaction Logs** | `.LOG1` and `.LOG2` files containing uncommitted registry transactions that AmcacheParser replays for complete data recovery |
| **NSRL (National Software Reference Library)** | NIST-maintained database of SHA-1 hashes for known commercial software, used as a whitelist to filter benign entries |

## Verification

- [ ] Amcache.hve and transaction logs (LOG1, LOG2) were collected from the forensic image
- [ ] AmcacheParser produced all expected CSV output files without errors
- [ ] SHA-1 hashes were extracted and checked against VirusTotal or CIRCL hashlookup
- [ ] Unsigned executables in suspicious paths have been flagged for further analysis
- [ ] Program entries show all software installations within the incident window
- [ ] Driver binaries have been checked for unsigned or out-of-box entries
- [ ] LinkDate vs. FileKeyLastWriteTimestamp comparison has been performed to tespit etmetimestomping
- [ ] Amcache Bul:ings are correlated with Prefetch and ShimCache for execution confirmation
- [ ] Final timeline integrates Amcache data with other forensic artifacts

---
name: performing-fuzzing-with-aflplusplus
description: Perform coverage-guided fuzzing of compiled binaries using AFL++ (American Fuzzy Lop Plus Plus) to discover memory corruption, crashes, and security vulnerabilities. The tester instruments
  target binaries with afl-cc/afl-clang-fast, manages input corpora with afl-cmin and afl-tmin, runs parallel fuzzing campaigns with afl-fuzz, and triages crashes using CASR or GDB scripts. Activates for
  requests involving binary fuzzing, crash discovery, coverage-guided testing, or AFL++ fuzzing campaigns.
tags:
- security-testing
- binary-analysis
- application-security
- siber-güvenlik
- crash-triage
- coverage-guided
- fetih
- web-application-security
- cybersecurity
- fuzzing
- aflplusplus
triggers:
- CSRF
- SQL injection
- XSS
- aflplusplus
- fuzzing
- incident
- log
- performing
- web güvenliği
- web security
category: web-application-security
source_subdomain: application-security
nist_csf:
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
adapted_for: fetih
---

# Performing Fuzzing with Aflplusplus


## Genel Bakış

AFL++ is a community-maintained fork of American Fuzzy Lop (AFL) that provides coverage-guided
fuzzing for compiled binaries. It instruments targets at compile time or via QEMU/Unicorn mode
for binary-only fuzzing, then mutates input corpora to discover new code paths. AFL++ includes
advanced scheduling (MOpt, rare), custom mutators, CMPLOG for input-to-state comparison solving,
and persistent mode for high-throughput fuzzing.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing fuzzing with aflplusplus
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- AFL++ kurulu (`apt install afl++` or build from source)
- Target binary source code (for compile-time instrumentation) or QEMU mode for binary-only
- Initial seed corpus of valid inputs for the target format
- Linux system with /proc/sys/kernel/core_pattern configured

## Adımlar

1. Instrument the target binary with `afl-cc` or `afl-clang-fast`
2. Prepare seed corpus directory with minimal valid inputs
3. Minimize corpus with `afl-cmin` to remove redundant seeds
4. Run `afl-fuzz` with appropriate flags (-i input -o output)
5. Monitor fuzzing progress via afl-whatsup and UI stats
6. Triage crashes with `afl-tmin` minimization and CASR/GDB analysis
7. Report unique crashes with reproduction steps

## Expected Output

```
+++ Bul:ings +++
  unique crashes: 12
  unique hangs: 3
  last crash: 00:02:15 ago
+++ Coverage +++
  map density: 4.23% / 8.41%
  paths found: 1847
  exec speed: 2145/sec
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 58d86dfb11d3f86c
-->


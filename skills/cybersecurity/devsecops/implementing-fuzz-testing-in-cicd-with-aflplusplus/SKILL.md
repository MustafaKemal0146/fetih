---
name: implementing-fuzz-testing-in-cicd-with-aflplusplus
description: Integrate AFL++ coverage-guided fuzz testing into CI/CD pipelines to discover memory corruption, input handling, and logic vulnerabilities in C/C++ and compiled applications.
tags:
- coverage-guided-fuzzing
- cicd
- security-testing
- vulnerability-discovery
- fetih
- devsecops
- cybersecurity
- afl
- siber-güvenlik
- aflplusplus
- fuzz-testing
triggers:
- aflplusplus
- cicd
- fuzz
- http
- implementing
- log
- testing
category: devsecops
source_subdomain: devsecops
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
adapted_for: fetih
---

# Implementing Fuzz Testing in Cicd with Aflplusplus


## Genel Bakış

AFL++ (American Fuzzy Lop Plus Plus) is a community-maintained fork of AFL that provides state-of-the-art coverage-guided fuzz testing for discovering vulnerabilities in compiled applications. AFL++ uses genetic algorithms to mutate inputs, tracking code coverage to Bul: new execution paths that trigger crashes, hangs, and undefined behavior. In CI/CD environments, AFL++ can be integrated to continuously test parsers, protocol handlers, file format processors, and any code that handles untrusted input. AFL++ supports persistent mode for high-speed fuzzing (up to 100,000+ executions per second), custom mutators, QEMU mode for binary-only fuzzing, and CmpLog/RedQueen for automatic dictionary extraction.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing fuzz testing in cicd with aflplusplus capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Linux-based CI runners (AFL++ does not support Windows natively)
- GCC or Clang compiler toolchain
- AFL++ kurulu (`apt install aflplusplus` or built from source)
- Target application with harness functions isolating input processing
- Seed corpus of valid input samples

## Core Concepts

### Coverage-Guided Fuzzing

AFL++ instruments the target binary at compile time (or via QEMU/Frida for binary-only targets) to track which code paths each input exercises. When a mutated input triggers a new code path, it is saved to the corpus for further mutation. This feedback loop enables AFL++ to systematically explore program state space.

### Instrumentation Modes

| Mode | Use Case | Performance |
|------|----------|-------------|
| `afl-clang-fast` (LTO) | Source available, best performance | Highest |
| `afl-clang-fast` | Source available, standard | High |
| `afl-gcc-fast` | GCC-based projects | High |
| `QEMU mode` | Binary-only, no source | Medium |
| `Frida mode` | Binary-only, cross-platform | Medium |
| `Unicorn mode` | Firmware, embedded | Low |

### Persistent Mode

Persistent mode avoids fork overhead by fuzzing within a loop:

```c
#include <unistd.h>

__AFL_FUZZ_INIT();

int main() {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        // Process buf[0..len-1]
        parse_input(buf, len);
    }
    return 0;
}
```

## İş Akışı

### Adım 1 --- Şunu inşa et: Fuzzing Harness

Şunu oluştur: harness that feeds AFL++ input to the target function:

```c
// fuzz_harness.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "target_parser.h"

__AFL_FUZZ_INIT();

int main() {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 4) continue;

        // Reset state between iterations
        parser_context_t ctx;
        parser_init(&ctx);
        parser_process(&ctx, buf, len);
        parser_cleanup(&ctx);
    }
    return 0;
}
```

### Adım 2 --- Compile with AFL++ Instrumentation

```bash
export CC=afl-clang-fast
export CXX=afl-clang-fast++

export AFL_USE_ASAN=1

$CC -o fuzz_harness fuzz_harness.c -ltarget_parser -fsanitize=address

$CC -o fuzz_harness_cmplog fuzz_harness.c -ltarget_parser \
  -fsanitize=address -DCMPLOG
```

### Adım 3 --- Prepare Seed Corpus

```bash
mkdir -p corpus/
cp test_inputs/* corpus/
afl-cmin -i corpus/ -o corpus_min/ -- ./fuzz_harness @@
mkdir -p corpus_tmin/
for f in corpus_min/*; do
    afl-tmin -i "$f" -o "corpus_tmin/$(basename $f)" -- ./fuzz_harness @@
done
```

### Adım 4 --- Configure CI/CD Integration

**GitHub Actions:**

```yaml
name: Fuzz Testing
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Nightly fuzzing

jobs:
  fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@v4

      - name: Install AFL++
        run: |
          sudo apt-get update
          sudo apt-get install -y aflplusplus

      - name: Restore corpus cache
        uses: actions/cache@v4
        with:
          path: corpus/
          key: fuzz-corpus-${{ github.sha }}
          restore-keys: fuzz-corpus-

      - name: Build fuzzing harness
        run: |
          export CC=afl-clang-fast
          export AFL_USE_ASAN=1
          make fuzz_harness

      - name: Run AFL++ fuzzing (CI mode)
        env:
          AFL_CMPLOG_ONLY_NEW: 1
          AFL_FAST_CAL: 1
          AFL_NO_STARTUP_CALIBRATION: 1
        run: |
          mkdir -p Bul:ings/
          timeout 7200 afl-fuzz \
            -S ci_fuzzer \
            -i corpus/ \
            -o Bul:ings/ \
            -t 5000 \
            -- ./fuzz_harness @@ || true

      - name: Check for crashes
        run: |
          CRASHES=$(Bul: Bul:ings/ -path "*/crashes/*" -not -name "README.txt" | wc -l)
          echo "Found $CRASHES unique crashes"
          if [ "$CRASHES" -gt 0 ]; then
            echo "::error::AFL++ found $CRASHES crashes"
            for crash in Bul:ings/*/crashes/*; do
              [ -f "$crash" ] && echo "Crash: $crash ($(wc -c < $crash) bytes)"
            done
            exit 1
          fi

      - name: Update corpus cache
        if: always()
        run: |
          afl-cmin -i Bul:ings/ci_fuzzer/queue/ -o corpus/ -- ./fuzz_harness @@
```

### Adım 5 --- Parallel Fuzzing for Nightly Runs

```bash
for i in $(seq 1 $(nproc)); do
    afl-fuzz -S fuzzer_$i \
      -i corpus/ \
      -o Bul:ings/ \
      -- ./fuzz_harness @@ &
done

wait

afl-cmin -i Bul:ings/*/queue/ -o corpus_merged/ -- ./fuzz_harness @@
```

### Adım 6 --- Crash Triage

```bash
for crash in Bul:ings/*/crashes/*; do
    echo "=== Testing: $crash ==="
    timeout 5 ./fuzz_harness_asan "$crash" 2>&1 | head -20
    echo "---"
done

afl-collect Bul:ings/ crashes_deduped/ -- ./fuzz_harness @@
```

## CI/CD Best Practices for AFL++

| Setting | CI Short Run | Nightly Long Run |
|---------|-------------|-----------------|
| Duration | 30-60 min | 4-24 hours |
| Mode | `-S` (secondary only) | `-S` (no `-M` for CI) |
| `AFL_CMPLOG_ONLY_NEW` | 1 | 1 |
| `AFL_FAST_CAL` | 1 | 0 |
| `AFL_NO_STARTUP_CALIBRATION` | 1 | 0 |
| Corpus caching | Required | Required |
| Parallel instances | 1-2 | nproc |

## Monitoring Fuzzing Campaigns

```bash
afl-whatsup Bul:ings/

```

## References

- [AFL++ Documentation](https://aflplus.plus/docs/)
- [AFL++ GitHub Repository](https://github.com/AFLplusplus/AFLplusplus)
- [AFL++ Fuzzing in Depth Guide](https://aflplus.plus/docs/fuzzing_in_depth/)
- [Google Testing Handbook - AFL++](https://appsec.guide/docs/fuzzing/c-cpp/aflpp/)
- [OWASP Fuzzing Guide](https://owasp.org/www-community/Fuzzing)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 503a0fc3ad0ee840
-->


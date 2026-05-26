---
name: sqli-test-generator
description: >
  Generate SQL injection test payloads for authorized security testing. Database-specific payloads for MySQL, PostgreSQL, MSSQL, Oracle.
tags: [sqli, test, payload, injection, imported]
triggers:
  - "sql injection test"
  - "sqli payload"
  - "generate sqli"
  - "sql injection payload"
  - "database test"
category: web-application-security
mitre_attack: [T1190, T1059]
nist_csf: [DE.CM-8, PR.IP-3]
adapted_for: fetih
source: Eyadkelleh/awesome-claude-skills-security
---

# SQL Injection Testing Assistant

You are helping with authorized SQL injection security testing. The user has proper authorization to test the target system.

## Your Task

1. Ask the user about their testing context:
   - What type of database? (MySQL, PostgreSQL, MSSQL, Oracle, etc.)
   - What injection point? (GET parameter, POST data, header, etc.)
   - What type of injection? (Error-based, Union-based, Blind, Time-based)
   - Any WAF or filtering detected?

2. Based on their answers, provide:
   - Appropriate SQL injection payloads from the fuzzing references
   - Testing methodology and order of operations
   - Payload encoding suggestions if needed
   - Detection and bypass techniques

3. Use the fuzzing wordlists from `seclists-categories fuzzing/fuzzing/references/Fuzzing/`:
   - `quick-SQLi.txt` - Quick initial tests
   - `Generic-SQLi.txt` - Generic payloads
   - `MySQL.fuzzdb.txt` - MySQL-specific
   - `PostgreSQL.fuzzdb.txt` - PostgreSQL-specific
   - `sqli.auth.bypass.txt` - Authentication bypass

## Important Reminders

⚠️ **CRITICAL**: Only use these payloads for:
- Authorized penetration testing with written permission
- Bug bounty programs within documented scope
- CTF competitions and challenges
- Testing your own systems

❌ **NEVER**: Use against systems without explicit authorization

## Example Workflow

```
1. Initial detection: Use quick-SQLi.txt payloads
2. Confirm vulnerability: Test for error messages or behavior changes
3. Determine database type: Use version detection payloads
4. Exploit: Use database-specific payloads
5. Document findings: Record all successful payloads
```

Provide practical, ethical guidance for the security testing task.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 41def7e9dc00464a
-->


# CTF Flag Format Kataloğu — 40+ Format

Bilinen CTF flag formatları. Auto-solver Stage 5'te doğrulama için kullanılır.

---

## Uluslararası CTF Yarışmaları

| Yarışma | Flag Formatı | Regex |
|---------|-------------|-------|
| DEF CON CTF | `OOO{...}` | `OOO\{[^}]+\}` |
| DEF CON Quals | `OOO{...}` | `OOO\{[^}]+\}` |
| HackTheBox | `HTB{...}` | `HTB\{[^}]+\}` |
| HackTheBox (yeni) | `HTB\{...\}` | `HTB\\{[^}]+\\}` |
| picoCTF | `picoCTF{...}` | `picoCTF\{[^}]+\}` |
| CSAW CTF | `flag{...}` | `flag\{[^}]+\}` |
| Real World CTF | `rwctf{...}` | `rwctf\{[^}]+\}` |
| Google CTF | `CTF{...}` | `CTF\{[^}]+\}` |
| Plaid CTF | `PCTF{...}` | `PCTF\{[^}]+\}` |
| Codegate | `CODEGATE{...}` | `CODEGATE\{[^}]+\}` |
| SECCON | `SECCON{...}` | `SECCON\{[^}]+\}` |
| HITCON | `hitcon{...}` | `hitcon\{[^}]+\}` |
| BCTF | `BCTF{...}` | `BCTF\{[^}]+\}` |
| 0CTF | `0ctf{...}` | `0ctf\{[^}]+\}` |
| ASIS CTF | `ASIS{...}` | `ASIS\{[^}]+\}` |
| VolgaCTF | `VolgaCTF{...}` | `VolgaCTF\{[^}]+\}` |
| Insomni'hack | `INS{...}` | `INS\{[^}]+\}` |
| TAMUctf | `gigem{...}` | `gigem\{[^}]+\}` |
| UTCTF | `utflag{...}` | `utflag\{[^}]+\}` |
| AngstromCTF | `actf{...}` | `actf\{[^}]+\}` |
| redpwnCTF | `flag{...}` | `flag\{[^}]+\}` |
| DawgCTF | `DawgCTF{...}` | `DawgCTF\{[^}]+\}` |
| UMass CTF | `UMASS{...}` | `UMASS\{[^}]+\}` |
| SunshineCTF | `sun{...}` | `sun\{[^}]+\}` |
| N00bCTF | `n00b{...}` | `n00b\{[^}]+\}` |

---

## Türk CTF Yarışmaları

| Yarışma | Flag Formatı | Regex |
|---------|-------------|-------|
| **Siber Vatan** | `SiberVatan{...}` | `[Ss][Ii][Bb][Ee][Rr][Vv][Aa][Tt][Aa][Nn]\{[^}]+\}` |
| **Siber Vatan (upper)** | `SIBERVATAN{...}` | `SIBERVATAN\{[^}]+\}` |
| **Siber Vatan (lower)** | `sibervatan{...}` | `sibervatan\{[^}]+\}` |
| Yavuzkraft (oyun-CTF) | `SiberVatan{...}` | (Siber Vatan ile aynı) |
| STM CTF | `STMCTF{...}` | `STMCTF\{[^}]+\}` |
| Baykar CTF | `BAYKAR{...}` | `BAYKAR\{[^}]+\}` |
| TÜBİTAK CTF | `TUBITAK{...}` | `TUBITAK\{[^}]+\}` |
| Hacktrick | `HACKTRICK{...}` | `HACKTRICK\{[^}]+\}` |
| Boğaziçi CTF | `BOUN{...}` | `BOUN\{[^}]+\}` |

---

## Asya CTF Yarışmaları

| Yarışma | Flag Formatı | Regex |
|---------|-------------|-------|
| ACSC (Asian Cyber Security Challenge) | `ACSC{...}` | `ACSC\{[^}]+\}` |
| CISC (Canadian International Security Challenge) | `CISC{...}` | `CISC\{[^}]+\}` |

---

## Genel / Bilinmeyen Formatlar

| Format | Regex |
|--------|-------|
| flag | `flag\{[^}]+\}` |
| FLAG | `FLAG\{[^}]+\}` |
| CTF | `CTF\{[^}]+\}` |
| ctf | `ctf\{[^}]+\}` |
| FLG | `FLG\{[^}]+\}` |
| Answer | `Answer\{[^}]+\}` |
| Key | `Key\{[^}]+\}` |
| Genel (any word) | `[A-Za-z0-9_]+\{[^}]+\}` |

---

## Grep Komutu (Tüm Formatlar İçin Tek Seferde)

```bash
grep -roP '[A-Za-z0-9_]+\{[^}]+\}' ./challenge_directory/
```

Siber Vatan özel:
```bash
grep -roP '[Ss][Ii][Bb][Ee][Rr][Vv][Aa][Tt][Aa][Nn]\{[^}]+\}' ./
```

---

## Sahte Flag Tespiti

Bazı challenge'larda **trap flag**'ler (sahte/yanıltıcı flag) bulunur:

- `flag{this_is_not_the_real_flag}` 
- `flag{keep_looking}`
- `flag{troll}`
- `flag{nice_try}`
- `flag{you_wish}`
- `flag{you_thought_it_was_that_easy}`
- Bir challenge'da 2+ flag varsa, genellikle sadece 1 tanesi gerçektir

**Strateji:** Birden fazla flag bulunursa hepsini flags.txt'ye kaydet, flag formatına en uygun olanı seç.

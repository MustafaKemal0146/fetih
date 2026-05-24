# Yavuzkraft — Minecraft-Themed Web Game Walkthrough

**Challenge**: Web game with resource gathering, password-protected mining, and multi-stage portal navigation.

## Stage 1: Overworld Entry

**Captcha**: SVG-based pixel art (Minecraft block font). Numbers rendered as white pixels on dark background. Solve by brute-force (100 combos max) or SVG path analysis.

**URL**: `POST https://web-d2b63e41.hacker.zone/` with `oyuncu_adi` + `captcha_cevap`

**Response**: 302 redirect to `/overworld.php` — this is where ALL subsequent actions happen.

## Stage 2: Resource Gathering

All POSTs go to `/overworld.php`. Each button maps to a POST parameter name. The form has no HTML `<form>` element — it's a raw POST.

| Action | POST data | Requirement |
|--------|-----------|-------------|
| Odun Topla | `odun_topla=1` | None (always active) |
| Tas Topla | `tas_topla=1` | 5 Odun |
| Demir Topla | `demir_topla=1` | 5 Tas |
| Elmas Kır | `elmas_sifre=PASSWORD&elmas_topla=1` | 5 Demir + password |
| Obsidyen Topla | `obsidyen_topla=1` | 5 Elmas |
| Nether Portal | `nether_portal=1` | 10 Obsidyen |

Run each 5 times to accumulate resources.

## Stage 3: Elmas Şifresi

The password input has `pattern="^!Y[a-z]{6}r\d{3}$"` — this is the format:
- `!Y` literal prefix
- 6 lowercase letters
- `r` literal
- 3 digits

Try Turkish/Minecraft-themed 6-letter words: `madeni` (mineshaft) → `!Ymadenir000`

The password is NOT client-side validated — the pattern is just a hint. The server validates it independently.

## Stage 4: Nether / End / Flag

After portal construction, navigate to `/nether.php` and then `/end.php`. The flag is at `/flag.php` — returns 302 if game incomplete.

## Key Insight

The hard part is the captcha (SVG brute-force). The password for elmas is guessable from Turkish context. The game stages are linear but require session persistence.

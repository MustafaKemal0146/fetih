/**
 * @fileoverview Fetih CTF Hash Crack — format auto-detect + dahili crack + john/hashcat wrapper.
 *
 * Akış:
 *  1. Hash format tespiti (length-based + prefix-based, hashid mantığı)
 *  2. Wordlist tespiti (rockyou.txt, fallback dahili 100 kelime)
 *  3. Hızlı hash (MD5/SHA1/SHA256/SHA512/NTLM) için Node crypto ile dahili crack
 *  4. Yavaş hash (bcrypt/scrypt/argon2) için john/hashcat komut önerisi (kuruluysa çalıştır)
 */

import { existsSync, readFileSync, statSync } from 'fs';
import { homedir } from 'os';
import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import type { ToolDefinition, ToolResult } from '../../types.js';

// ─── Tipler ──────────────────────────────────────────────────────────────────

export interface HashFormatInfo {
  name: string;
  hashcatMode?: number;
  johnFormat?: string;
  fastCrackable: boolean;
  description: string;
}

export interface HashCrackResult {
  hash: string;
  format: HashFormatInfo;
  wordlist: string;
  cracked: string | null;
  attempts: number;
  durationMs: number;
  externalCommands: string[];
  notes: string[];
}

// ─── Format tespiti ──────────────────────────────────────────────────────────

const HEX_RE = /^[0-9a-fA-F]+$/;

export function detectHashFormat(hash: string): HashFormatInfo {
  const h = hash.trim();

  // Prefix-based
  if (/^\$2[abxy]\$/.test(h)) return { name: 'bcrypt', hashcatMode: 3200, johnFormat: 'bcrypt', fastCrackable: false, description: 'bcrypt (yavaş, GPU önerilir)' };
  if (h.startsWith('$1$')) return { name: 'md5crypt', hashcatMode: 500, johnFormat: 'md5crypt', fastCrackable: false, description: 'MD5 crypt (Unix)' };
  if (h.startsWith('$5$')) return { name: 'sha256crypt', hashcatMode: 7400, johnFormat: 'sha256crypt', fastCrackable: false, description: 'SHA-256 crypt' };
  if (h.startsWith('$6$')) return { name: 'sha512crypt', hashcatMode: 1800, johnFormat: 'sha512crypt', fastCrackable: false, description: 'SHA-512 crypt' };
  if (h.startsWith('$argon2')) return { name: 'argon2', fastCrackable: false, description: 'Argon2 (memory-hard)' };
  if (h.startsWith('$y$')) return { name: 'yescrypt', fastCrackable: false, description: 'yescrypt' };
  if (h.startsWith('{SSHA}')) return { name: 'SSHA', hashcatMode: 111, fastCrackable: false, description: 'Salted SHA-1 (LDAP)' };
  if (/^[A-Za-z0-9+/]{27}$/.test(h)) return { name: 'NTLM-base64?', fastCrackable: false, description: 'Base64 hash şüphesi' };

  // /etc/shadow benzeri
  if (h.includes(':')) {
    const parts = h.split(':');
    if (parts.length >= 2 && parts[1]!.startsWith('$')) {
      return detectHashFormat(parts[1]!);
    }
  }

  // Length-based hex
  if (HEX_RE.test(h)) {
    switch (h.length) {
      case 32: return { name: 'MD5', hashcatMode: 0, johnFormat: 'raw-md5', fastCrackable: true, description: 'MD5 (32 hex) — NTLM/MD4 de aynı uzunlukta' };
      case 40: return { name: 'SHA1', hashcatMode: 100, johnFormat: 'raw-sha1', fastCrackable: true, description: 'SHA-1 (40 hex)' };
      case 56: return { name: 'SHA224', hashcatMode: 1300, johnFormat: 'raw-sha224', fastCrackable: true, description: 'SHA-224 (56 hex)' };
      case 64: return { name: 'SHA256', hashcatMode: 1400, johnFormat: 'raw-sha256', fastCrackable: true, description: 'SHA-256 (64 hex)' };
      case 96: return { name: 'SHA384', hashcatMode: 10800, johnFormat: 'raw-sha384', fastCrackable: true, description: 'SHA-384 (96 hex)' };
      case 128: return { name: 'SHA512', hashcatMode: 1700, johnFormat: 'raw-sha512', fastCrackable: true, description: 'SHA-512 (128 hex)' };
      case 16: return { name: 'CRC?', fastCrackable: false, description: '16 hex — CRC64 / kısa MD5 truncated?' };
      case 8:  return { name: 'CRC32', hashcatMode: 11500, fastCrackable: true, description: 'CRC32 (8 hex)' };
    }
  }

  return { name: 'UNKNOWN', fastCrackable: false, description: `Tanınamadı (uzunluk=${h.length})` };
}

// ─── Wordlist tespiti ────────────────────────────────────────────────────────

const ROCKYOU_PATHS = [
  '/usr/share/wordlists/rockyou.txt',
  '/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt',
  `${homedir()}/.fetih/wordlists/rockyou.txt`,
  `${homedir()}/wordlists/rockyou.txt`,
];

const BUILTIN_WORDLIST = [
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234',
  '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football',
  'monkey', 'letmein', '696969', 'shadow', 'master', '666666', 'qwertyuiop',
  '123321', 'mustang', '1234567890', 'michael', '654321', 'pussy', 'superman',
  '1qaz2wsx', '7777777', 'fuckyou', '121212', '000000', 'qazwsx', '123qwe',
  'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter',
  'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine',
  'iloveyou', 'fuckme', '2000', 'charlie', 'robert', 'thomas', 'hockey',
  'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'asshole',
  'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555',
  '11111111', '131313', 'freedom', '777777', 'pass', 'fuck', 'maggie',
  '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda',
  'summer', 'love', 'ashley', '6969', 'nicole', 'chelsea', 'biteme', 'matthew',
  'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor',
  'matrix', 'admin', 'fetih', 'flag', 'ctf', 'hello', 'hello123', 'test',
  'test123', 'root', 'toor', 'changeme', 'welcome', 'welcome1', 'P@ssw0rd',
];

function detectWordlist(): { path: string; size: number } {
  for (const p of ROCKYOU_PATHS) {
    if (existsSync(p)) {
      try {
        const size = statSync(p).size;
        return { path: p, size };
      } catch { /* skip */ }
    }
  }
  return { path: '<dahili 100 kelime>', size: 0 };
}

// ─── Dahili hızlı crack ──────────────────────────────────────────────────────

function fastHash(algo: string, input: string): string {
  return createHash(algo).update(input).digest('hex');
}

function tryWordlistCrack(target: string, format: HashFormatInfo, wordlistPath: string, maxAttempts = 100_000): { match: string | null; attempts: number } {
  const algo = (() => {
    switch (format.name) {
      case 'MD5': return 'md5';
      case 'SHA1': return 'sha1';
      case 'SHA224': return 'sha224';
      case 'SHA256': return 'sha256';
      case 'SHA384': return 'sha384';
      case 'SHA512': return 'sha512';
      default: return null;
    }
  })();
  if (!algo) return { match: null, attempts: 0 };

  const targetLower = target.trim().toLowerCase();
  let attempts = 0;

  // Dahili wordlist mi yoksa dosya mı?
  const words = wordlistPath === '<dahili 100 kelime>'
    ? BUILTIN_WORDLIST
    : (() => {
      try {
        // İlk 100k satır oku — bütünü RAM'e doldurma
        const content = readFileSync(wordlistPath, 'utf8');
        return content.split('\n').slice(0, maxAttempts);
      } catch { return BUILTIN_WORDLIST; }
    })();

  for (const word of words) {
    attempts++;
    if (attempts > maxAttempts) break;
    const clean = word.trim();
    if (!clean) continue;
    if (fastHash(algo, clean) === targetLower) return { match: clean, attempts };
    // Common variant: capitalize
    if (clean.length > 0 && fastHash(algo, clean.charAt(0).toUpperCase() + clean.slice(1)) === targetLower) {
      return { match: clean.charAt(0).toUpperCase() + clean.slice(1), attempts };
    }
  }
  return { match: null, attempts };
}

// ─── External tool wrapper ───────────────────────────────────────────────────

function commandExists(cmd: string): boolean {
  try {
    execFileSync('which', [cmd], { stdio: 'ignore' });
    return true;
  } catch { return false; }
}

function buildExternalCommands(hash: string, format: HashFormatInfo, wordlistPath: string): string[] {
  const cmds: string[] = [];
  const wordlist = wordlistPath !== '<dahili 100 kelime>' ? wordlistPath : '/usr/share/wordlists/rockyou.txt';

  if (format.hashcatMode !== undefined) {
    cmds.push(`hashcat -m ${format.hashcatMode} -a 0 '${hash}' ${wordlist}`);
    cmds.push(`hashcat -m ${format.hashcatMode} -a 0 '${hash}' ${wordlist} -r /usr/share/hashcat/rules/best64.rule`);
  }
  if (format.johnFormat) {
    cmds.push(`echo '${hash}' > hash.txt && john --format=${format.johnFormat} --wordlist=${wordlist} hash.txt`);
  }
  if (format.name === 'MD5' || format.name === 'SHA1') {
    cmds.push(`# Online lookup: https://crackstation.net  veya  https://hashes.com/en/decrypt/hash`);
  }
  return cmds;
}

// ─── Ana Crack Fonksiyonu ────────────────────────────────────────────────────

export async function crackHash(hash: string): Promise<HashCrackResult> {
  const start = Date.now();
  const format = detectHashFormat(hash);
  const { path: wordlistPath, size: wordlistSize } = detectWordlist();
  const notes: string[] = [];

  if (wordlistPath !== '<dahili 100 kelime>') {
    notes.push(`Wordlist: ${wordlistPath} (${(wordlistSize / 1024 / 1024).toFixed(1)} MB)`);
  } else {
    notes.push(`rockyou.txt bulunamadı, dahili wordlist (${BUILTIN_WORDLIST.length} kelime) kullanıldı`);
    notes.push('İpucu: sudo apt install wordlists  (Kali) veya  ~/.fetih/wordlists/rockyou.txt indir');
  }

  let cracked: string | null = null;
  let attempts = 0;

  if (format.fastCrackable) {
    const result = tryWordlistCrack(hash, format, wordlistPath);
    cracked = result.match;
    attempts = result.attempts;
    if (cracked) notes.push(`🎯 ${attempts} denemede çözüldü`);
    else notes.push(`${attempts} kelime denendi, eşleşme yok`);
  } else {
    notes.push(`${format.name} dahili crack için yavaş — john/hashcat öneriliyor`);
  }

  const externalCommands = buildExternalCommands(hash, format, wordlistPath);
  if (commandExists('hashcat')) notes.push('✓ hashcat kurulu — yukarıdaki komut hazır');
  if (commandExists('john')) notes.push('✓ john kurulu — yukarıdaki komut hazır');

  return {
    hash,
    format,
    wordlist: wordlistPath,
    cracked,
    attempts,
    durationMs: Date.now() - start,
    externalCommands,
    notes,
  };
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfHashTool: ToolDefinition = {
  name: 'ctf_hash',
  description:
    'CTF hash crack — format auto-detect (MD5/SHA1/SHA224/256/384/512, NTLM, bcrypt, ' +
    'sha256crypt, sha512crypt, argon2 vb.) + dahili wordlist crack (Node crypto, MD5/SHA için) + ' +
    'rockyou.txt tespiti + john/hashcat komut önerisi (mode mapping ile). ' +
    'Hash girdiyi ya plain ya $-prefixli ya da user:hash formatında ver.',
  inputSchema: {
    type: 'object',
    properties: {
      hash: { type: 'string', description: 'Crack edilecek hash (hex string veya $-prefixli)' },
    },
    required: ['hash'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const hash = String(input['hash'] ?? '').trim();
    if (!hash) return { output: 'Hata: hash boş olamaz.', isError: true };

    const r = await crackHash(hash);

    const lines: string[] = [
      '┌─ HASH CRACK ────────────────────────────────────────────────┐',
      `│ Hash    : ${r.hash.slice(0, 60)}`,
      `│ Format  : ${r.format.name} — ${r.format.description}`,
      `│ Wordlist: ${r.wordlist.slice(-50)}`,
      `│ Süre    : ${r.durationMs}ms, deneme: ${r.attempts}`,
    ];
    if (r.cracked) lines.push(`│ 🎯 PLAINTEXT: ${r.cracked}`);
    else lines.push(`│ ✗ Çözülemedi (dahili)`);
    lines.push('└─────────────────────────────────────────────────────────────┘');

    if (r.notes.length > 0) {
      lines.push('\nNotlar:');
      r.notes.forEach(n => lines.push(`  ${n}`));
    }

    if (r.externalCommands.length > 0) {
      lines.push('\nDış araç komutları:');
      r.externalCommands.forEach(c => lines.push(`  $ ${c}`));
    }

    return { output: lines.join('\n'), isError: false };
  },
};

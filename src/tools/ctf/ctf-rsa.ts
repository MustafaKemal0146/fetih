/**
 * @fileoverview Fetih CTF RSA Toolkit
 * Saldırılar: Fermat factorization (p,q yakın), Wiener (küçük d), factordb API,
 * Common modulus, küçük e (cube root), basic decrypt.
 */

import type { ToolDefinition, ToolResult } from '../../types.js';

// ─── BigInt yardımcıları ─────────────────────────────────────────────────────

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function modInverse(a: bigint, m: bigint): bigint | null {
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) return null;
  return ((oldS % m) + m) % m;
}

function bigintSqrt(n: bigint): bigint {
  if (n < 0n) throw new Error('negatif sayının karekökü yok');
  if (n < 2n) return n;
  // Newton-Raphson
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x;
}

function isqrt(n: bigint): bigint {
  return bigintSqrt(n);
}

function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) [a, b] = [b, a % b];
  return a < 0n ? -a : a;
}

// ─── 1. Fermat Factorization (p, q yakınsa) ──────────────────────────────────

export function fermatFactor(n: bigint, maxIter = 1_000_000): { p: bigint; q: bigint } | null {
  let a = isqrt(n);
  if (a * a < n) a += 1n;
  for (let i = 0; i < maxIter; i++) {
    const b2 = a * a - n;
    if (b2 >= 0n) {
      const b = isqrt(b2);
      if (b * b === b2) {
        const p = a - b;
        const q = a + b;
        if (p > 1n && q > 1n && p * q === n) return { p, q };
      }
    }
    a += 1n;
  }
  return null;
}

// ─── 2. Wiener Attack (küçük d) ──────────────────────────────────────────────

function continuedFraction(numerator: bigint, denominator: bigint): bigint[] {
  const result: bigint[] = [];
  while (denominator !== 0n) {
    result.push(numerator / denominator);
    [numerator, denominator] = [denominator, numerator % denominator];
  }
  return result;
}

function convergents(cf: bigint[]): Array<{ num: bigint; den: bigint }> {
  const result: Array<{ num: bigint; den: bigint }> = [];
  let h0 = 0n, h1 = 1n;
  let k0 = 1n, k1 = 0n;
  for (const a of cf) {
    const h = a * h1 + h0;
    const k = a * k1 + k0;
    result.push({ num: h, den: k });
    [h0, h1] = [h1, h];
    [k0, k1] = [k1, k];
  }
  return result;
}

export function wienerAttack(n: bigint, e: bigint): bigint | null {
  const cf = continuedFraction(e, n);
  const convs = convergents(cf);
  for (const { num: k, den: d } of convs) {
    if (k === 0n || d === 0n) continue;
    if ((e * d - 1n) % k !== 0n) continue;
    const phi = (e * d - 1n) / k;
    // p+q = n - phi + 1
    const s = n - phi + 1n;
    // p,q kökleri: x^2 - sx + n = 0
    const disc = s * s - 4n * n;
    if (disc < 0n) continue;
    const sq = isqrt(disc);
    if (sq * sq !== disc) continue;
    return d;
  }
  return null;
}

// ─── 3. factordb.com API lookup ──────────────────────────────────────────────

export async function factordbLookup(n: bigint): Promise<{ ok: boolean; factors: bigint[]; status: string }> {
  try {
    const res = await fetch(`http://factordb.com/api?query=${n.toString()}`, {
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return { ok: false, factors: [], status: `HTTP ${res.status}` };
    const json = await res.json() as { id?: string; status?: string; factors?: Array<[string, number]> };
    const status = json.status ?? 'UNKNOWN';
    // status: FF=fully factored, CF=composite factors, P=prime, C=composite no factor
    const factors: bigint[] = [];
    for (const [factor, exp] of json.factors ?? []) {
      for (let i = 0; i < exp; i++) factors.push(BigInt(factor));
    }
    return { ok: status === 'FF' || factors.length >= 2, factors, status };
  } catch (err) {
    return { ok: false, factors: [], status: `Hata: ${String(err).slice(0, 100)}` };
  }
}

// ─── 4. Common Modulus Attack ────────────────────────────────────────────────

/** İki ayrı e ile aynı n için iki ciphertext (c1, c2) varsa ve gcd(e1, e2) = 1 → m bulunabilir */
export function commonModulusAttack(n: bigint, e1: bigint, e2: bigint, c1: bigint, c2: bigint): bigint | null {
  // Extended Euclidean: a*e1 + b*e2 = 1
  let [oldR, r] = [e1, e2];
  let [oldS, s] = [1n, 0n];
  let [oldT, t] = [0n, 1n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  if (oldR !== 1n) return null; // gcd != 1
  // m = c1^a * c2^b mod n
  const a = oldS, b = oldT;
  const part1 = a < 0n ? modInverse(modPow(c1, -a, n), n) : modPow(c1, a, n);
  const part2 = b < 0n ? modInverse(modPow(c2, -b, n), n) : modPow(c2, b, n);
  if (part1 === null || part2 === null) return null;
  return (part1 * part2) % n;
}

// ─── 5. Küçük e (e=3) Kübik Kök ──────────────────────────────────────────────

/** m^3 < n ise direkt küp kök al (padding yoksa) */
export function smallECubeRoot(c: bigint, e: bigint = 3n): bigint | null {
  if (e !== 3n) return null;
  // c^(1/3) tam sayı kök
  let lo = 0n, hi = c;
  while (lo <= hi) {
    const mid = (lo + hi) / 2n;
    const cube = mid * mid * mid;
    if (cube === c) return mid;
    if (cube < c) lo = mid + 1n;
    else hi = mid - 1n;
  }
  return null;
}

// ─── 6. RSA Decrypt (p, q biliniyor) ─────────────────────────────────────────

export function rsaDecrypt(c: bigint, p: bigint, q: bigint, e: bigint): { m: bigint; text: string } | null {
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const d = modInverse(e, phi);
  if (d === null) return null;
  const m = modPow(c, d, n);
  let hex = m.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const text = Buffer.from(hex, 'hex').toString('utf8');
  return { m, text };
}

// ─── BigInt parse (hex/dec) ──────────────────────────────────────────────────

function parseBigInt(s: string): bigint {
  const trimmed = s.trim();
  if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) return BigInt(trimmed);
  return BigInt(trimmed);
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfRsaTool: ToolDefinition = {
  name: 'ctf_rsa',
  description:
    'CTF RSA toolkit — saldırı kütüphanesi. Eylemler: ' +
    'fermat (p,q yakın factorization), wiener (küçük d), ' +
    'factordb (online factordb.com lookup), common_modulus (aynı n iki e), ' +
    'small_e (küçük e kübik kök), decrypt (p,q,e,c → m). ' +
    'RSA challenge\'larında ilk adım: factordb dene, sonra fermat, sonra wiener.',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['fermat', 'wiener', 'factordb', 'common_modulus', 'small_e', 'decrypt', 'auto'] },
      n: { type: 'string', description: 'modulus (decimal veya 0xhex)' },
      e: { type: 'string', description: 'public exponent' },
      e1: { type: 'string', description: 'common_modulus için ilk e' },
      e2: { type: 'string', description: 'common_modulus için ikinci e' },
      c: { type: 'string', description: 'ciphertext' },
      c1: { type: 'string', description: 'common_modulus için c1' },
      c2: { type: 'string', description: 'common_modulus için c2' },
      p: { type: 'string', description: 'decrypt için p' },
      q: { type: 'string', description: 'decrypt için q' },
    },
    required: ['action'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const action = String(input['action'] ?? '');
    const get = (k: string) => input[k] ? parseBigInt(String(input[k])) : null;

    try {
      switch (action) {
        case 'fermat': {
          const n = get('n'); if (!n) return { output: 'n gerekli', isError: true };
          const r = fermatFactor(n);
          if (!r) return { output: 'Fermat başarısız (p, q yeterince yakın değil)', isError: true };
          return { output: `✓ Fermat:\n  p = ${r.p}\n  q = ${r.q}`, isError: false };
        }
        case 'wiener': {
          const n = get('n'); const e = get('e');
          if (!n || !e) return { output: 'n ve e gerekli', isError: true };
          const d = wienerAttack(n, e);
          if (d === null) return { output: 'Wiener başarısız (d yeterince küçük değil)', isError: true };
          return { output: `✓ Wiener:\n  d = ${d}`, isError: false };
        }
        case 'factordb': {
          const n = get('n'); if (!n) return { output: 'n gerekli', isError: true };
          const r = await factordbLookup(n);
          const lines = [`Status: ${r.status}`, `Factors (${r.factors.length}):`, ...r.factors.map(f => `  ${f}`)];
          return { output: lines.join('\n'), isError: !r.ok };
        }
        case 'common_modulus': {
          const n = get('n'), e1 = get('e1'), e2 = get('e2'), c1 = get('c1'), c2 = get('c2');
          if (!n || !e1 || !e2 || !c1 || !c2) return { output: 'n, e1, e2, c1, c2 gerekli', isError: true };
          const m = commonModulusAttack(n, e1, e2, c1, c2);
          if (m === null) return { output: 'gcd(e1,e2) != 1 — saldırı uygulanamaz', isError: true };
          let hex = m.toString(16); if (hex.length % 2) hex = '0' + hex;
          const text = Buffer.from(hex, 'hex').toString('utf8');
          return { output: `✓ m = ${m}\nhex: ${hex}\nutf8: ${text}`, isError: false };
        }
        case 'small_e': {
          const c = get('c'); const e = get('e') ?? 3n;
          if (!c) return { output: 'c gerekli', isError: true };
          const m = smallECubeRoot(c, e);
          if (m === null) return { output: 'Tam küp kök bulunamadı (m^e == c değil — padding olabilir)', isError: true };
          let hex = m.toString(16); if (hex.length % 2) hex = '0' + hex;
          return { output: `✓ m = ${m}\nutf8: ${Buffer.from(hex, 'hex').toString('utf8')}`, isError: false };
        }
        case 'decrypt': {
          const p = get('p'), q = get('q'), e = get('e'), c = get('c');
          if (!p || !q || !e || !c) return { output: 'p, q, e, c gerekli', isError: true };
          const r = rsaDecrypt(c, p, q, e);
          if (!r) return { output: 'Decrypt başarısız (modInverse yok)', isError: true };
          return { output: `✓ m = ${r.m}\nutf8: ${r.text}`, isError: false };
        }
        case 'auto': {
          // n, e, c verilirse: factordb → fermat → wiener sırasıyla dene
          const n = get('n'), e = get('e'), c = get('c');
          if (!n || !e) return { output: 'n ve e gerekli', isError: true };
          const lines: string[] = ['# Otomatik RSA saldırı zinciri'];

          // 1. factordb
          lines.push('\n[1] factordb.com lookup...');
          const fdb = await factordbLookup(n);
          lines.push(`    Status: ${fdb.status}`);
          if (fdb.ok && fdb.factors.length === 2 && c) {
            const r = rsaDecrypt(c, fdb.factors[0]!, fdb.factors[1]!, e);
            if (r) {
              lines.push(`✓ ÇÖZÜLDÜ (factordb):`, `  p = ${fdb.factors[0]}`, `  q = ${fdb.factors[1]}`, `  m = ${r.m}`, `  utf8: ${r.text}`);
              return { output: lines.join('\n'), isError: false };
            }
          }

          // 2. Fermat
          lines.push('\n[2] Fermat factorization...');
          const ff = fermatFactor(n, 100_000);
          if (ff && c) {
            const r = rsaDecrypt(c, ff.p, ff.q, e);
            if (r) {
              lines.push(`✓ ÇÖZÜLDÜ (Fermat):`, `  p = ${ff.p}`, `  q = ${ff.q}`, `  m = ${r.m}`, `  utf8: ${r.text}`);
              return { output: lines.join('\n'), isError: false };
            }
          } else {
            lines.push('    Fermat başarısız');
          }

          // 3. Wiener
          lines.push('\n[3] Wiener attack...');
          const d = wienerAttack(n, e);
          if (d !== null && c) {
            const m = modPow(c, d, n);
            let hex = m.toString(16); if (hex.length % 2) hex = '0' + hex;
            const text = Buffer.from(hex, 'hex').toString('utf8');
            lines.push(`✓ ÇÖZÜLDÜ (Wiener):`, `  d = ${d}`, `  m = ${m}`, `  utf8: ${text}`);
            return { output: lines.join('\n'), isError: false };
          } else {
            lines.push('    Wiener başarısız');
          }

          lines.push('\n✗ Hiçbir otomatik saldırı işe yaramadı. Manuel: küçük e cube root, common modulus, LLL...');
          return { output: lines.join('\n'), isError: true };
        }
        default:
          return { output: `Bilinmeyen eylem: ${action}`, isError: true };
      }
    } catch (err) {
      return { output: `Hata: ${err instanceof Error ? err.message : String(err)}`, isError: true };
    }
  },
};

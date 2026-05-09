/**
 * @fileoverview CTF Integration Tests — gerçek challenge'larda flag bulma doğrulaması.
 * Her test bir CTF kategorisini temsil eder: encoding, classical crypto, ASCII,
 * stego (PNG LSB), file carving, embedded strings, web SQLi, network basic auth, auto dispatcher.
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, mkdirSync, rmSync, existsSync } from 'fs';
import { join } from 'path';

import { solve } from '../src/tools/ctf/ctf-solver.js';
import { analyzeFile } from '../src/tools/ctf/ctf-file-analyzer.js';
import { analyzeSteganography } from '../src/tools/ctf/ctf-stego.js';
import { analyzeWeb } from '../src/tools/ctf/ctf-web-analyzer.js';
import { analyzeNetwork } from '../src/tools/ctf/ctf-network-analyzer.js';
import { ctfAutoTool, autoAnalyze } from '../src/tools/ctf/ctf-auto.js';

const FIXTURE_DIR = join(process.cwd(), 'tests', 'fixtures', 'ctf-tmp');

// ─── Yardımcı: PNG LSB-R encode (R kanalına bit gömme) ──────────────────────

async function buildLsbRPng(outPath: string, message: string, width = 64, height = 64): Promise<void> {
  const jimpModule = await import('jimp');
  const Jimp = (jimpModule.default ?? jimpModule) as any;
  const img = new Jimp(width, height, 0xFF000000); // siyah opak

  // Mesajı bit dizisine çevir (MSB-first per byte) + null terminator
  const bytes = Buffer.from(message + '\0', 'utf8');
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  }

  // Her pikselin R kanalı LSB'sini ilgili bit ile değiştir
  for (let i = 0; i < bits.length && i < width * height; i++) {
    const idx = i * 4;
    const r = img.bitmap.data[idx];
    img.bitmap.data[idx] = (r & 0xFE) | bits[i];
  }

  await img.writeAsync(outPath);
}

// ─── Yardımcı: Caesar shift ──────────────────────────────────────────────────

function caesarShift(s: string, shift: number): string {
  return s.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90)  return String.fromCharCode(((code - 65 + shift) % 26 + 26) % 26 + 65);
    if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + shift) % 26 + 26) % 26 + 97);
    return c;
  }).join('');
}

// ─── Setup / Teardown ────────────────────────────────────────────────────────

beforeAll(() => {
  if (existsSync(FIXTURE_DIR)) rmSync(FIXTURE_DIR, { recursive: true, force: true });
  mkdirSync(FIXTURE_DIR, { recursive: true });
});

afterAll(() => {
  if (existsSync(FIXTURE_DIR)) rmSync(FIXTURE_DIR, { recursive: true, force: true });
});

// ─── 1. Multi-layer encoding (Hex → Base64) ─────────────────────────────────

describe('CTF: Encoding/Crypto Solver', () => {
  test('multi-layer (Base64 → Hex → flag)', () => {
    const flag = 'flag{multi_layer_easy}';
    const hex = Buffer.from(flag, 'utf8').toString('hex');
    const b64 = Buffer.from(hex, 'utf8').toString('base64');

    const result = solve(b64);
    expect(result.flag).toBe(flag);
    expect(result.layers.length).toBeGreaterThanOrEqual(2);
  });

  test('Caesar shift 7', () => {
    const flag = 'flag{caesar7}';
    const encoded = caesarShift(flag, 7); // mshn{jhlzhy7}

    const result = solve(encoded);
    expect(result.flag).toBe(flag);
  });

  test('ASCII decimal', () => {
    const flag = 'flag{ascii}';
    const encoded = Array.from(flag).map(c => c.charCodeAt(0)).join(' ');

    const result = solve(encoded);
    expect(result.flag).toBe(flag);
    expect(result.technique.toLowerCase()).toContain('ascii');
  });

  test('Hex tek katman', () => {
    const flag = 'flag{hex_only}';
    const hex = Buffer.from(flag, 'utf8').toString('hex');

    const result = solve(hex);
    expect(result.flag).toBe(flag);
  });
});

// ─── 2. Stego: PNG LSB-R ─────────────────────────────────────────────────────

describe('CTF: Steganography', () => {
  test('PNG LSB-R kanalında gizli flag', async () => {
    const flag = 'flag{lsb_red}';
    const pngPath = join(FIXTURE_DIR, 'lsb_red.png');
    await buildLsbRPng(pngPath, flag, 64, 64);

    const result = await analyzeSteganography(pngPath);
    const allFlags = result.results.flatMap(r => r.flagsFound);
    expect(allFlags).toContain(flag);
    expect(result.bestResult).not.toBeNull();
    expect(result.bestResult!.flagsFound).toContain(flag);
  }, 30_000);
});

// ─── 3. File analyzer: carving + embedded strings ────────────────────────────

describe('CTF: File Analyzer', () => {
  test('JPEG sonuna eklenmiş ZIP (file carving)', async () => {
    // Minimal JPEG (SOI + APP0/JFIF + EOI) + ZIP local file header
    const jpegHeader = Buffer.from([
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ]);
    const jpegBody = Buffer.alloc(64, 0xAA); // dummy payload
    const jpegEoi = Buffer.from([0xFF, 0xD9]);
    // Minimal ZIP local file header for "flag.txt" (flags=0, no actual compressed data)
    const zipHeader = Buffer.concat([
      Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00]),
      Buffer.from('flag.txt', 'utf8'),
    ]);
    const buf = Buffer.concat([jpegHeader, jpegBody, jpegEoi, zipHeader]);
    const path = join(FIXTURE_DIR, 'carved.jpg');
    writeFileSync(path, buf);

    const result = await analyzeFile(path);
    expect(result.detectedType).toBe('JPEG');
    expect(result.carvedFiles.length).toBeGreaterThan(0);
    const types = result.carvedFiles.map(c => c.type);
    expect(types.some(t => t === 'ZIP' || t === 'JPEG_APPENDED_DATA')).toBe(true);
  });

  test('Binary dosyada gömülü flag string\'i', async () => {
    const flag = 'flag{embedded_in_binary}';
    const buf = Buffer.concat([
      Buffer.alloc(32, 0x00),
      Buffer.from(flag, 'utf8'),
      Buffer.alloc(32, 0xFF),
    ]);
    const path = join(FIXTURE_DIR, 'binary.bin');
    writeFileSync(path, buf);

    const result = await analyzeFile(path);
    expect(result.flagsFound).toContain(flag);
  });
});

// ─── 4. Web analyzer: SQLi tespiti ───────────────────────────────────────────

describe('CTF: Web Analyzer', () => {
  test('SQL hata mesajı + tek tırnaklı parametre', () => {
    const input = [
      'GET /products?id=1%27 HTTP/1.1',
      'Host: shop.example.com',
      '',
      'HTTP/1.1 500 Internal Server Error',
      'Content-Type: text/html',
      '',
      "<html><body>You have an error in your SQL syntax near 'id=1'' at line 1</body></html>",
    ].join('\n');

    const result = analyzeWeb(input);
    const sqlVulns = result.vulnerabilities_found.filter(v => v.type.includes('SQL'));
    expect(sqlVulns.length).toBeGreaterThan(0);
    expect(sqlVulns.some(v => v.severity === 'critical' || v.severity === 'high')).toBe(true);
    expect(result.tools_suggested.some(t => t.includes('sqlmap'))).toBe(true);
  });

  test('Response gövdesinde flag bulma', () => {
    const input = [
      'GET /admin HTTP/1.1',
      'Host: target.tld',
      '',
      '<html><body>flag{web_response_leak}</body></html>',
    ].join('\n');

    const result = analyzeWeb(input);
    expect(result.flags_found).toContain('flag{web_response_leak}');
  });
});

// ─── 5. Network analyzer: HTTP Basic Auth + DNS TXT ──────────────────────────

describe('CTF: Network Analyzer', () => {
  test('HTTP Basic Auth credential decode (flag içerir)', () => {
    const cred = 'admin:flag{basic_auth_solved}';
    const b64 = Buffer.from(cred, 'utf8').toString('base64');
    const input = `GET /secret HTTP/1.1\nHost: target.tld\nAuthorization: Basic ${b64}\n`;

    const result = analyzeNetwork(input);
    expect(result.credentials_found.length).toBeGreaterThan(0);
    expect(result.credentials_found.some(c => c.includes('flag{basic_auth_solved}'))).toBe(true);
  });

  test('DNS TXT record\'unda flag', () => {
    const input = [
      'example.com. IN TXT "flag{dns_txt_record}"',
      'example.com. IN TXT "v=spf1 -all"',
    ].join('\n');

    const result = analyzeNetwork(input);
    expect(result.flags_found).toContain('flag{dns_txt_record}');
  });
});

// ─── 6. Auto dispatcher: type detect + doğru modül çağrısı ───────────────────

describe('CTF: Auto Dispatcher', () => {
  test('Encoding girdisini otomatik solver\'a yönlendirir', async () => {
    const flag = 'flag{auto_dispatched}';
    const hex = Buffer.from(flag, 'utf8').toString('hex');
    const b64 = Buffer.from(hex, 'utf8').toString('base64');

    const report = await autoAnalyze(b64);
    expect(report.auto_detected_type).toBe('encoding');
    expect(report.modules_run).toContain('ctf_solver');
    expect(report.solved).toBe(true);
    expect(report.flag).toBe(flag);
  });

  test('PNG dosya path\'ini stego/file modüllerine yönlendirir', async () => {
    const pngPath = join(FIXTURE_DIR, 'auto_lsb.png');
    await buildLsbRPng(pngPath, 'flag{auto_stego}', 64, 64);

    const report = await autoAnalyze(pngPath);
    expect(report.auto_detected_type).toBe('file_image');
    expect(report.modules_run).toContain('ctf_stego');
    expect(report.modules_run).toContain('ctf_file_analyzer');
    expect(report.flag).toBe('flag{auto_stego}');
  }, 30_000);

  test('ctfAutoTool.execute() çıktısında flag görünür', async () => {
    const flag = 'flag{tool_execute_path}';
    const hex = Buffer.from(flag, 'utf8').toString('hex');
    const b64 = Buffer.from(hex, 'utf8').toString('base64');

    const result = await ctfAutoTool.execute({ input: b64 }, process.cwd());
    expect(result.isError).toBeFalsy();
    expect(result.output).toContain(flag);
  });
});

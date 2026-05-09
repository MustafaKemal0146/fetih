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
import { analyzeAudio } from '../src/tools/ctf/ctf-audio-analyzer.js';
import { analyzeBinary } from '../src/tools/ctf/ctf-binary-analyzer.js';
import { detectHashFormat, crackHash } from '../src/tools/ctf/ctf-hash.js';
import { createHash, createHmac } from 'crypto';

// CTF Canavarı v4.1 imports
import { cyclicPattern, cyclicFind, checksec, getShellcode } from '../src/tools/ctf/ctf-pwn.js';
import { decodeJwt, algNoneAttack, bruteForceJwtSecret, forgeJwt } from '../src/tools/ctf/ctf-jwt.js';
import { fermatFactor, wienerAttack, commonModulusAttack, smallECubeRoot, rsaDecrypt } from '../src/tools/ctf/ctf-rsa.js';
import { detectEcb, aesEcbDecrypt } from '../src/tools/ctf/ctf-aes-helper.js';
import { parsePcap, largeFileStringsSweep } from '../src/tools/ctf/ctf-forensics.js';
import { classifyChallenge } from '../src/tools/ctf/ctf-classify.js';
import { interactiveSessionTool } from '../src/tools/ctf/interactive-session.js';
import { createCipheriv } from 'crypto';

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

// ─── 7. EXIF derin tarama (JPEG COM marker) ─────────────────────────────────

describe('CTF: EXIF Derin Tarama', () => {
  test('JPEG COM marker içinde gizli flag', async () => {
    const flag = 'flag{exif_com_marker}';
    // Minimal JPEG: SOI + COM(flag) + APP0/JFIF + EOI
    const soi = Buffer.from([0xFF, 0xD8]);
    const flagBytes = Buffer.from(flag, 'utf8');
    const comLen = flagBytes.length + 2; // length field includes itself
    const comLenBuf = Buffer.alloc(2); comLenBuf.writeUInt16BE(comLen, 0);
    const comMarker = Buffer.concat([
      Buffer.from([0xFF, 0xFE]), comLenBuf, flagBytes,
    ]);
    const app0 = Buffer.from([
      0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00,
      0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ]);
    const eoi = Buffer.from([0xFF, 0xD9]);
    const buf = Buffer.concat([soi, comMarker, app0, eoi]);
    const path = join(FIXTURE_DIR, 'exif_com.jpg');
    writeFileSync(path, buf);

    const r = await analyzeFile(path);
    expect(r.detectedType).toBe('JPEG');
    expect(r.flagsFound).toContain(flag);
  });
});

// ─── 8. Audio analyzer (WAV LSB) ────────────────────────────────────────────

describe('CTF: Audio Analyzer', () => {
  test('WAV LSB sample bytes flag tespiti', async () => {
    const flag = 'flag{wav_lsb}';
    // Minimal 16-bit mono WAV, sample LSB'lerine flag bit'lerini göm
    const message = flag + '\0';
    const bits: number[] = [];
    for (const ch of Buffer.from(message, 'utf8')) {
      for (let b = 7; b >= 0; b--) bits.push((ch >> b) & 1);
    }
    const sampleRate = 8000;
    const sampleCount = Math.max(bits.length, 1024);
    const dataSize = sampleCount * 2; // 16-bit = 2 bytes per sample

    // RIFF header
    const buf = Buffer.alloc(44 + dataSize);
    buf.write('RIFF', 0);
    buf.writeUInt32LE(36 + dataSize, 4);
    buf.write('WAVE', 8);
    buf.write('fmt ', 12);
    buf.writeUInt32LE(16, 16);          // fmt chunk size
    buf.writeUInt16LE(1, 20);           // PCM
    buf.writeUInt16LE(1, 22);           // mono
    buf.writeUInt32LE(sampleRate, 24);
    buf.writeUInt32LE(sampleRate * 2, 28); // byte rate
    buf.writeUInt16LE(2, 32);           // block align
    buf.writeUInt16LE(16, 34);          // bits per sample
    buf.write('data', 36);
    buf.writeUInt32LE(dataSize, 40);

    // Samples — düşük amplitüd, LSB'leri mesaj
    for (let i = 0; i < sampleCount; i++) {
      const bit = i < bits.length ? bits[i]! : 0;
      const sampleValue = 0x0100 | bit; // small positive sample with bit in LSB
      buf.writeInt16LE(sampleValue, 44 + i * 2);
    }

    const path = join(FIXTURE_DIR, 'lsb.wav');
    writeFileSync(path, buf);

    const r = await analyzeAudio(path);
    expect(r.detectedFormat).toBe('WAV');
    const lsbModule = r.modules.find(m => m.module === 'WAV-LSB');
    expect(lsbModule).toBeDefined();
    expect(lsbModule!.flagsFound).toContain(flag);
  }, 60_000);
});

// ─── 9. Binary analyzer (gerçek ELF: Node binary) ───────────────────────────

describe('CTF: Binary Analyzer', () => {
  test('gerçek küçük ELF binary tespiti ve sembol analizi', async () => {
    // Küçük bir sistem binary'si seç (büyük node binary timeout yapabilir)
    const candidates = ['/bin/ls', '/bin/cat', '/bin/echo', '/usr/bin/whoami'];
    const realBin = candidates.find(p => existsSync(p));
    if (!realBin) {
      console.log('Test skip: hiçbir küçük ELF binary bulunamadı');
      return;
    }
    const r = await analyzeBinary(realBin);
    expect(r.fileType.toLowerCase()).toContain('elf');
    const strSec = r.sections.find(s => s.module === 'strings');
    expect(strSec).toBeDefined();
    expect(strSec!.ok).toBe(true);
    const readelfSec = r.sections.find(s => s.module === 'readelf -h -l');
    expect(readelfSec).toBeDefined();
  }, 30_000);

  test('flag içeren binary (ham buffer)', async () => {
    const flag = 'flag{binary_strings}';
    // ELF magic + dummy + flag string + dummy
    const buf = Buffer.concat([
      Buffer.from([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]),
      Buffer.alloc(64, 0x00),
      Buffer.from(flag, 'utf8'),
      Buffer.alloc(64, 0xFF),
    ]);
    const path = join(FIXTURE_DIR, 'fake.elf');
    writeFileSync(path, buf);

    const r = await analyzeBinary(path);
    expect(r.flagsFound).toContain(flag);
  });
});

// ─── 10. Hash crack ──────────────────────────────────────────────────────────

describe('CTF: Hash Crack', () => {
  test('format detection: MD5 (32 hex)', () => {
    const r = detectHashFormat('5d41402abc4b2a76b9719d911017c592'); // md5("hello")
    expect(r.name).toBe('MD5');
    expect(r.fastCrackable).toBe(true);
    expect(r.hashcatMode).toBe(0);
  });

  test('format detection: SHA256 (64 hex)', () => {
    const r = detectHashFormat(createHash('sha256').update('test').digest('hex'));
    expect(r.name).toBe('SHA256');
    expect(r.hashcatMode).toBe(1400);
  });

  test('format detection: bcrypt prefix', () => {
    const r = detectHashFormat('$2b$12$abcdefghijklmnopqrstuvwxyz0123456789012345678901234');
    expect(r.name).toBe('bcrypt');
    expect(r.fastCrackable).toBe(false);
  });

  test('MD5 dahili wordlist crack — "password"', async () => {
    const target = createHash('md5').update('password').digest('hex');
    const r = await crackHash(target);
    expect(r.format.name).toBe('MD5');
    expect(r.cracked).toBe('password');
    expect(r.attempts).toBeGreaterThan(0);
  });

  test('SHA1 dahili wordlist crack — "admin"', async () => {
    const target = createHash('sha1').update('admin').digest('hex');
    const r = await crackHash(target);
    expect(r.format.name).toBe('SHA1');
    expect(r.cracked).toBe('admin');
  });
});

// ─── 11. Auto dispatcher: hash & binary route ───────────────────────────────

describe('CTF: Auto Dispatcher Yeni Tipler', () => {
  test('hash girdisini ctf_hash modülüne yönlendirir', async () => {
    const target = createHash('md5').update('letmein').digest('hex');
    const report = await autoAnalyze(target);
    expect(report.auto_detected_type).toBe('hash');
    expect(report.modules_run).toContain('ctf_hash');
    expect(report.flag).toBe('letmein');
  });

  test('ELF dosyasını binary analyzer\'a yönlendirir', async () => {
    const flag = 'flag{auto_binary}';
    const buf = Buffer.concat([
      Buffer.from([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]),
      Buffer.alloc(32, 0x00),
      Buffer.from(flag, 'utf8'),
      Buffer.alloc(32, 0xFF),
    ]);
    const path = join(FIXTURE_DIR, 'auto.elf');
    writeFileSync(path, buf);

    const report = await autoAnalyze(path);
    expect(report.auto_detected_type).toBe('file_binary');
    expect(report.modules_run).toContain('ctf_binary_analyzer');
    expect(report.flag).toBe(flag);
  });

  test('WAV dosyasını audio analyzer\'a yönlendirir', async () => {
    // Yeni dosya — basitleştirilmiş WAV (sadece tip tespiti için, flag aramayız)
    const sampleRate = 8000, sampleCount = 256, dataSize = sampleCount * 2;
    const buf = Buffer.alloc(44 + dataSize);
    buf.write('RIFF', 0); buf.writeUInt32LE(36 + dataSize, 4); buf.write('WAVE', 8);
    buf.write('fmt ', 12); buf.writeUInt32LE(16, 16); buf.writeUInt16LE(1, 20);
    buf.writeUInt16LE(1, 22); buf.writeUInt32LE(sampleRate, 24);
    buf.writeUInt32LE(sampleRate * 2, 28); buf.writeUInt16LE(2, 32); buf.writeUInt16LE(16, 34);
    buf.write('data', 36); buf.writeUInt32LE(dataSize, 40);
    const path = join(FIXTURE_DIR, 'auto.wav');
    writeFileSync(path, buf);

    const report = await autoAnalyze(path);
    expect(report.auto_detected_type).toBe('file_audio');
    expect(report.modules_run).toContain('ctf_audio_analyzer');
  }, 60_000);
});

// ─── 12. PWN: Cyclic pattern + checksec ──────────────────────────────────────

describe('CTF Canavarı: PWN', () => {
  test('cyclic pattern roundtrip — offset bul', () => {
    const pattern = cyclicPattern(256);
    expect(pattern.length).toBe(256);
    // İlk 4 karakter "aaaa" — offset 0
    expect(cyclicFind('aaaa')).toBe(0);
    // 100. byte'tan sonraki 4 karakteri al ve geri bul
    const slice4 = pattern.slice(120, 124);
    expect(cyclicFind(slice4)).toBe(120);
  });

  test('shellcode katalogu — execve_sh varlığı', () => {
    const sc = getShellcode('linux/x64/execve_sh');
    expect(sc).not.toBeNull();
    expect(sc!.sizeBytes).toBeGreaterThan(0);
    expect(sc!.bytes).toContain('\\x');
  });

  test('checksec gerçek küçük ELF üzerinde', () => {
    const candidates = ['/bin/ls', '/bin/cat', '/bin/echo'];
    const realBin = candidates.find(p => existsSync(p));
    if (!realBin) return; // skip
    const c = checksec(realBin);
    expect(c.ok).toBe(true);
    expect(c.arch).not.toBe('unknown');
    expect(['enabled', 'disabled', 'unknown']).toContain(c.nx);
    expect(['pie', 'no-pie', 'unknown']).toContain(c.pie);
  }, 15_000);
});

// ─── 13. JWT toolkit ────────────────────────────────────────────────────────

describe('CTF Canavarı: JWT', () => {
  test('decode standart JWT', () => {
    // header={alg:HS256,typ:JWT} payload={user:admin}
    const headerB64 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
    const payloadB64 = 'eyJ1c2VyIjoiYWRtaW4ifQ';
    const token = `${headerB64}.${payloadB64}.fakesignature`;
    const r = decodeJwt(token);
    expect(r.ok).toBe(true);
    expect((r.header as any).alg).toBe('HS256');
    expect((r.payload as any).user).toBe('admin');
  });

  test('alg:none saldırı — admin claim ekle', () => {
    const token = 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.sig';
    const r = algNoneAttack(token, { admin: true, user: 'admin' });
    expect(r.ok).toBe(true);
    expect(r.forged).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$/); // boş signature
    const decoded = decodeJwt(r.forged);
    expect((decoded.header as any).alg).toBe('none');
    expect((decoded.payload as any).admin).toBe(true);
  });

  test('HMAC HS256 brute-force — zayıf secret "secret"', async () => {
    // Gerçek bir HS256 token üret (secret="secret")
    const headerB64 = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64')
      .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const payloadB64 = Buffer.from('{"sub":"test"}').toString('base64')
      .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const sig = createHmac('sha256', 'secret').update(`${headerB64}.${payloadB64}`).digest('base64')
      .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const token = `${headerB64}.${payloadB64}.${sig}`;
    const r = await bruteForceJwtSecret(token, 1000);
    expect(r.ok).toBe(true);
    expect(r.cracked).toBe('secret');
  }, 20_000);

  test('forge ile claim ekle ve decode et', () => {
    const original = 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.x';
    const forged = forgeJwt('mysecret', { user: 'admin', role: 'superuser' }, original);
    const decoded = decodeJwt(forged);
    expect(decoded.ok).toBe(true);
    expect((decoded.payload as any).role).toBe('superuser');
    // İmzayı yeniden doğrula
    const parts = forged.split('.');
    const expectedSig = createHmac('sha256', 'mysecret').update(`${parts[0]}.${parts[1]}`).digest('base64')
      .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    expect(parts[2]).toBe(expectedSig);
  });
});

// ─── 14. RSA derin ──────────────────────────────────────────────────────────

describe('CTF Canavarı: RSA', () => {
  test('Fermat factorization — yakın p,q', () => {
    // p, q yakın asal seç (manuel doğrulanmış)
    const p = 1000000007n;
    const q = 1000000009n;
    const n = p * q;
    const r = fermatFactor(n);
    expect(r).not.toBeNull();
    // p ve q bizim seçtiğimizle eşleşmeli (sıra değişebilir)
    const found = [r!.p, r!.q].sort();
    expect(found[0]).toBe(p);
    expect(found[1]).toBe(q);
  });

  test('Wiener attack — küçük d', () => {
    // Wiener: d < (1/3) * n^(1/4) olmalı
    // p = 65537, q = 65539, n = 4295229443
    // Toy example: p,q seç + küçük d, e hesapla
    const p = 65537n;
    const q = 65539n;
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    // d küçük; gcd(d, phi)=1 olmalı. d=5 seç.
    const d = 5n;
    // Modular inverse
    const modInv = (a: bigint, m: bigint): bigint => {
      let [oldR, r] = [a, m];
      let [oldS, s] = [1n, 0n];
      while (r !== 0n) { const q = oldR / r; [oldR, r] = [r, oldR - q * r]; [oldS, s] = [s, oldS - q * s]; }
      return ((oldS % m) + m) % m;
    };
    const e = modInv(d, phi);
    const recovered = wienerAttack(n, e);
    expect(recovered).toBe(d);
  });

  test('common modulus attack', () => {
    const p = 1009n, q = 1013n;
    const n = p * q;
    const e1 = 17n, e2 = 13n;
    const m = 12345n;
    // c1 = m^e1 mod n, c2 = m^e2 mod n
    const modPow = (b: bigint, e: bigint, m: bigint): bigint => {
      let result = 1n; b = b % m;
      while (e > 0n) { if (e & 1n) result = (result * b) % m; e >>= 1n; b = (b * b) % m; }
      return result;
    };
    const c1 = modPow(m, e1, n);
    const c2 = modPow(m, e2, n);
    const recovered = commonModulusAttack(n, e1, e2, c1, c2);
    expect(recovered).toBe(m);
  });

  test('küçük e (e=3) cube root', () => {
    const m = 42n;
    const c = m * m * m; // 74088
    const r = smallECubeRoot(c, 3n);
    expect(r).toBe(m);
  });

  test('rsaDecrypt — ascii roundtrip', () => {
    const p = 1009n, q = 1013n;
    const e = 17n;
    const message = 'Hi'; // küçük (n = 1022117)
    // m = bytes
    const m = BigInt('0x' + Buffer.from(message).toString('hex'));
    const modPow = (b: bigint, e: bigint, m: bigint): bigint => {
      let result = 1n; b = b % m;
      while (e > 0n) { if (e & 1n) result = (result * b) % m; e >>= 1n; b = (b * b) % m; }
      return result;
    };
    const n = p * q;
    expect(m).toBeLessThan(n);
    const c = modPow(m, e, n);
    const r = rsaDecrypt(c, p, q, e);
    expect(r).not.toBeNull();
    expect(r!.text).toBe(message);
  });
});

// ─── 15. AES ECB pattern detect ─────────────────────────────────────────────

describe('CTF Canavarı: AES', () => {
  test('ECB tekrar pattern tespiti', () => {
    // Aynı plaintext block'unu üç defa şifrele — ECB tekrar yapar
    const key = Buffer.alloc(16, 0x42);
    const iv = Buffer.alloc(16, 0); // ECB'de IV yok ama API gerektirir
    const block = Buffer.alloc(16, 0x55);
    const plain = Buffer.concat([block, block, block, Buffer.alloc(16, 0xAA)]);
    const cipher = createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const r = detectEcb(ct);
    expect(r.isLikelyEcb).toBe(true);
    expect(r.duplicateBlocks).toBeGreaterThan(0);
  });

  test('ECB random plaintext — tespit etmez', () => {
    const key = Buffer.alloc(16, 0x42);
    // Random 64 byte
    const plain = Buffer.from(Array.from({ length: 64 }, () => Math.floor(Math.random() * 256)));
    const cipher = createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const r = detectEcb(ct);
    expect(r.isLikelyEcb).toBe(false);
  });

  test('ECB decrypt — key ile roundtrip', () => {
    const key = Buffer.alloc(16, 0x11);
    const plain = Buffer.from('CTF Test Block16'); // tam 16 byte
    const cipher = createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const r = aesEcbDecrypt(ct, key);
    expect(r.ok).toBe(true);
    expect(r.plaintext).toBe('CTF Test Block16');
  });
});

// ─── 16. Forensics: PCAP parse ──────────────────────────────────────────────

describe('CTF Canavarı: Forensics', () => {
  test('minimal PCAP buffer parse', () => {
    // PCAP global header (24 byte) + 1 paket (16 byte header + ethernet+IP+TCP+payload)
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0xA1B2C3D4, 0); // little-endian magic
    header.writeUInt16LE(2, 4); // version major
    header.writeUInt16LE(4, 6); // version minor
    header.writeUInt32LE(0, 8); // thiszone
    header.writeUInt32LE(0, 12); // sigfigs
    header.writeUInt32LE(65535, 16); // snaplen
    header.writeUInt32LE(1, 20); // linktype = Ethernet

    // Paket: ethernet (14) + IPv4 (20) + TCP (20) + payload "GET /flag HTTP/1.1"
    const payload = Buffer.from('GET /flag HTTP/1.1\r\n');
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(12345, 0); // srcPort
    tcp.writeUInt16BE(80, 2);     // dstPort
    tcp[12] = 5 << 4;             // data offset = 5 (20 byte)
    const ip = Buffer.alloc(20);
    ip[0] = 0x45;                 // IPv4 + IHL=5
    ip.writeUInt16BE(20 + 20 + payload.length, 2); // total length
    ip[9] = 6;                    // protocol = TCP
    ip[12] = 192; ip[13] = 168; ip[14] = 1; ip[15] = 1;   // src IP
    ip[16] = 10;  ip[17] = 0;   ip[18] = 0;   ip[19] = 1; // dst IP
    const eth = Buffer.alloc(14);
    eth.writeUInt16BE(0x0800, 12); // ethertype IPv4
    const packetData = Buffer.concat([eth, ip, tcp, payload]);

    const pktHeader = Buffer.alloc(16);
    pktHeader.writeUInt32LE(1700000000, 0);
    pktHeader.writeUInt32LE(0, 4);
    pktHeader.writeUInt32LE(packetData.length, 8);
    pktHeader.writeUInt32LE(packetData.length, 12);

    const pcap = Buffer.concat([header, pktHeader, packetData]);
    const r = parsePcap(pcap);
    expect(r.ok).toBe(true);
    expect(r.format).toBe('pcap');
    expect(r.totalPackets).toBe(1);
    expect(r.uniqueIps).toContain('192.168.1.1');
    expect(r.uniqueIps).toContain('10.0.0.1');
    expect(r.protocols['TCP']).toBe(1);
    expect(r.httpRequests).toContain('GET /flag');
  });

  test('strings sweep — gömülü flag', () => {
    const flag = 'flag{forensics_sweep}';
    const buf = Buffer.concat([
      Buffer.alloc(1024, 0x00),
      Buffer.from(flag, 'utf8'),
      Buffer.alloc(1024, 0xFF),
    ]);
    const path = join(FIXTURE_DIR, 'sweep.bin');
    writeFileSync(path, buf);
    const r = largeFileStringsSweep(path, 512);
    expect(r.flags).toContain(flag);
    expect(r.bytesScanned).toBeGreaterThan(0);
  });
});

// ─── 17. Classify ───────────────────────────────────────────────────────────

describe('CTF Canavarı: Classify', () => {
  test('PWN challenge metni', () => {
    const r = classifyChallenge('Buffer overflow vulnerable binary, exploit me. nc challenge.tld 1337');
    expect(r.category).toBe('pwn');
    expect(r.confidence).toBeGreaterThan(20);
  });

  test('Hash challenge metni', () => {
    const r = classifyChallenge('Crack this MD5: 5d41402abc4b2a76b9719d911017c592');
    expect(r.category).toBe('hash');
  });

  test('JWT challenge metni', () => {
    const r = classifyChallenge('Forge this JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.x');
    expect(r.category).toBe('jwt');
  });

  test('mobile challenge metni', () => {
    const r = classifyChallenge('Reverse this APK and find the flag in classes.dex');
    expect(r.category).toBe('mobile');
  });

  test('unknown için default kategori', () => {
    const r = classifyChallenge('hello world how are you today');
    expect(['unknown', 'misc']).toContain(r.category);
  });
});

// ─── 18. Interactive session ────────────────────────────────────────────────

describe('CTF Canavarı: Interactive Session', () => {
  test('bash spawn → echo → kill', async () => {
    // start
    const startRes = await interactiveSessionTool.execute({
      action: 'start', command: 'bash', args: ['-c', 'while read line; do echo "ECHO: $line"; done'],
    }, process.cwd());
    expect(startRes.isError).toBeFalsy();
    const sidMatch = startRes.output.match(/Session başladı: (s\d+)/);
    expect(sidMatch).not.toBeNull();
    const sid = sidMatch![1];

    // sendline
    await interactiveSessionTool.execute({
      action: 'sendline', session: sid, data: 'hello',
    }, process.cwd());

    // recv_until
    const recvRes = await interactiveSessionTool.execute({
      action: 'recv_until', session: sid, pattern: 'ECHO: hello', timeout: 3000,
    }, process.cwd());
    expect(recvRes.isError).toBeFalsy();
    expect(recvRes.output).toContain('ECHO: hello');

    // kill
    const killRes = await interactiveSessionTool.execute({
      action: 'kill', session: sid,
    }, process.cwd());
    expect(killRes.isError).toBeFalsy();
  }, 10_000);
});

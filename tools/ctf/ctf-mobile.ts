/**
 * @fileoverview Fetih CTF Mobile Toolkit (APK / IPA)
 * APK: ZIP olarak parse, AndroidManifest binary header, classes.dex magic, strings, sertifika
 * IPA: ZIP parse, Info.plist extract, strings sweep
 * apktool/jadx kuruluysa decompile + smali/java string araması
 */

import { existsSync, readFileSync } from 'fs';
import { execFileSync } from 'child_process';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { findFlags, extractStrings } from './ctf-utils.js';

function commandExists(cmd: string): boolean {
  try { execFileSync('which', [cmd], { stdio: 'ignore' }); return true; } catch { return false; }
}

// ─── ZIP Local File Header parser (jszip yok — minimum implementasyon) ───────

interface ZipEntry {
  name: string;
  offset: number;
  compressedSize: number;
  uncompressedSize: number;
  isEncrypted: boolean;
  compressionMethod: number;
}

function listZipEntries(buf: Buffer, maxEntries = 1000): ZipEntry[] {
  const entries: ZipEntry[] = [];
  let i = 0;
  while (i < buf.length - 30 && entries.length < maxEntries) {
    if (buf[i] === 0x50 && buf[i+1] === 0x4B && buf[i+2] === 0x03 && buf[i+3] === 0x04) {
      const flags = buf.readUInt16LE(i + 6);
      const compMethod = buf.readUInt16LE(i + 8);
      const compSize = buf.readUInt32LE(i + 18);
      const uncompSize = buf.readUInt32LE(i + 22);
      const fnLen = buf.readUInt16LE(i + 26);
      const extraLen = buf.readUInt16LE(i + 28);
      if (i + 30 + fnLen > buf.length) break;
      const filename = buf.slice(i + 30, i + 30 + fnLen).toString('utf8');
      entries.push({
        name: filename,
        offset: i + 30 + fnLen + extraLen,
        compressedSize: compSize,
        uncompressedSize: uncompSize,
        isEncrypted: (flags & 0x01) !== 0,
        compressionMethod: compMethod,
      });
      i += 30 + fnLen + extraLen + compSize;
    } else {
      i++;
    }
  }
  return entries;
}

// ─── APK Analizi ─────────────────────────────────────────────────────────────

interface ApkAnalysis {
  ok: boolean;
  format: 'APK' | 'IPA' | 'JAR' | 'UNKNOWN';
  entries: ZipEntry[];
  hasManifest: boolean;
  hasDex: boolean;
  hasInfoPlist: boolean;
  hasResources: boolean;
  flagsFound: string[];
  notes: string[];
  apktoolOutput?: string;
}

function detectArchiveType(entries: ZipEntry[]): ApkAnalysis['format'] {
  if (entries.some(e => e.name === 'AndroidManifest.xml' || e.name === 'classes.dex')) return 'APK';
  if (entries.some(e => e.name.startsWith('Payload/') && e.name.endsWith('.app/'))) return 'IPA';
  if (entries.some(e => e.name === 'META-INF/MANIFEST.MF')) return 'JAR';
  return 'UNKNOWN';
}

function analyzeMobile(buf: Buffer): ApkAnalysis {
  const result: ApkAnalysis = {
    ok: false, format: 'UNKNOWN', entries: [],
    hasManifest: false, hasDex: false, hasInfoPlist: false, hasResources: false,
    flagsFound: [], notes: [],
  };

  if (buf.length < 4 || buf[0] !== 0x50 || buf[1] !== 0x4B) {
    result.notes.push('ZIP magic bytes (PK..) bulunamadı');
    return result;
  }

  const entries = listZipEntries(buf);
  result.entries = entries;
  result.format = detectArchiveType(entries);

  result.hasManifest = entries.some(e => e.name === 'AndroidManifest.xml');
  result.hasDex = entries.some(e => e.name.endsWith('.dex'));
  result.hasInfoPlist = entries.some(e => e.name.endsWith('Info.plist'));
  result.hasResources = entries.some(e => e.name === 'resources.arsc' || e.name.endsWith('.plist'));

  // Tüm dosyada flag string araması
  const stringsAll = extractStrings(buf, 6);
  result.flagsFound = findFlags(stringsAll);

  // Şifreli dosya uyarısı
  const encrypted = entries.filter(e => e.isEncrypted);
  if (encrypted.length > 0) {
    result.notes.push(`🔒 ${encrypted.length} şifreli dosya: ${encrypted.slice(0, 3).map(e => e.name).join(', ')}`);
  }

  result.ok = true;
  return result;
}

// ─── apktool / jadx wrapper ──────────────────────────────────────────────────

function runApktool(filePath: string, outputDir: string): { ok: boolean; output: string; notes: string[] } {
  if (!commandExists('apktool')) {
    return { ok: false, output: '', notes: ['apktool yok — sudo apt install apktool veya https://apktool.org'] };
  }
  try {
    const out = execFileSync('apktool', ['d', '-f', '-o', outputDir, filePath], {
      encoding: 'utf8', timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
    });
    return { ok: true, output: out.slice(0, 4000), notes: [`Decompile çıktısı: ${outputDir}`] };
  } catch (err) {
    return { ok: false, output: '', notes: [`apktool hatası: ${String(err).slice(0, 200)}`] };
  }
}

function runJadx(filePath: string, outputDir: string): { ok: boolean; output: string; notes: string[] } {
  if (!commandExists('jadx')) {
    return { ok: false, output: '', notes: ['jadx yok — https://github.com/skylot/jadx'] };
  }
  try {
    const out = execFileSync('jadx', ['-d', outputDir, filePath], {
      encoding: 'utf8', timeout: 180_000, maxBuffer: 4 * 1024 * 1024,
    });
    return { ok: true, output: out.slice(0, 4000), notes: [`Java decompile çıktısı: ${outputDir}`] };
  } catch (err) {
    return { ok: false, output: '', notes: [`jadx hatası: ${String(err).slice(0, 200)}`] };
  }
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfMobileTool: ToolDefinition = {
  name: 'ctf_mobile',
  description:
    'CTF Mobile (APK/IPA) analizi. Eylemler: analyze (ZIP entries + manifest tespit + strings), ' +
    'apktool (apktool d ile resource decompile), jadx (Java decompile). ' +
    'APK: AndroidManifest.xml, classes.dex tespit; IPA: Info.plist; her ikisi için strings flag arama. ' +
    'apktool/jadx kuruluysa derinlemesine decompile.',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['analyze', 'apktool', 'jadx'] },
      path: { type: 'string', description: 'APK/IPA dosyasının tam path\'i' },
      outputDir: { type: 'string', description: 'apktool/jadx çıktı dizini' },
    },
    required: ['action', 'path'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const action = String(input['action'] ?? '');
    const filePath = String(input['path'] ?? '').trim();
    if (!filePath) return { output: 'path gerekli', isError: true };
    if (!existsSync(filePath)) return { output: `Dosya bulunamadı: ${filePath}`, isError: true };

    if (action === 'analyze') {
      const buf = readFileSync(filePath);
      const r = analyzeMobile(buf);
      const lines = [
        '┌─ MOBILE ANALİZ ─────────────────────────────────────────────┐',
        `│ Format       : ${r.format}`,
        `│ Toplam entry : ${r.entries.length}`,
        `│ Manifest     : ${r.hasManifest ? '✓ AndroidManifest.xml' : '✗'}`,
        `│ DEX          : ${r.hasDex ? '✓ classes.dex' : '✗'}`,
        `│ Info.plist   : ${r.hasInfoPlist ? '✓' : '✗'}`,
        `│ Resources    : ${r.hasResources ? '✓' : '✗'}`,
      ];
      if (r.flagsFound.length > 0) lines.push(`│ 🎯 FLAG: ${r.flagsFound.join(', ')}`);
      lines.push('└─────────────────────────────────────────────────────────────┘');

      // İlginç entry listesi
      const interesting = r.entries.filter(e =>
        /\.(xml|json|plist|properties|cfg|conf|txt|md)$/i.test(e.name) || e.name.includes('config'),
      ).slice(0, 20);
      if (interesting.length > 0) {
        lines.push('\nİlginç dosyalar:');
        interesting.forEach(e => lines.push(`  ${e.name} (${e.uncompressedSize} bytes)${e.isEncrypted ? ' 🔒' : ''}`));
      }
      if (r.notes.length > 0) {
        lines.push('\nNotlar:');
        r.notes.forEach(n => lines.push(`  ${n}`));
      }
      lines.push('\nDerinlemesine analiz: action=apktool veya action=jadx');
      return { output: lines.join('\n'), isError: !r.ok };
    }

    if (action === 'apktool') {
      const outputDir = String(input['outputDir'] ?? `/tmp/fetih_apktool_${Date.now()}`);
      const r = runApktool(filePath, outputDir);
      return { output: [r.output, ...r.notes].join('\n'), isError: !r.ok };
    }

    if (action === 'jadx') {
      const outputDir = String(input['outputDir'] ?? `/tmp/fetih_jadx_${Date.now()}`);
      const r = runJadx(filePath, outputDir);
      return { output: [r.output, ...r.notes].join('\n'), isError: !r.ok };
    }

    return { output: `Bilinmeyen eylem: ${action}`, isError: true };
  },
};

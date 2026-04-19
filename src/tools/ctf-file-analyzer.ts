/**
 * @fileoverview Seth CTF Dosya Analizi — Magic bytes, EXIF, strings, file carving
 */

import { readFileSync, existsSync } from 'fs';
import { extname } from 'path';
import type { ToolDefinition, ToolResult } from '../types.js';
import { extractStrings, findFlags, detectMagicType } from './ctf-utils.js';

// ─── Magic Bytes Tablosu ─────────────────────────────────────────────────────

// MAGIC_SIGNATURES — carveFiles için yerel (ext bilgisi gerekli)
const MAGIC_SIGNATURES: Array<{ bytes: number[]; type: string; ext: string }> = [
  { bytes: [0xFF, 0xD8, 0xFF],             type: 'JPEG',  ext: '.jpg' },
  { bytes: [0x89, 0x50, 0x4E, 0x47],       type: 'PNG',   ext: '.png' },
  { bytes: [0x47, 0x49, 0x46, 0x38],       type: 'GIF',   ext: '.gif' },
  { bytes: [0x25, 0x50, 0x44, 0x46],       type: 'PDF',   ext: '.pdf' },
  { bytes: [0x50, 0x4B, 0x03, 0x04],       type: 'ZIP',   ext: '.zip' },
  { bytes: [0x52, 0x61, 0x72, 0x21],       type: 'RAR',   ext: '.rar' },
  { bytes: [0x7F, 0x45, 0x4C, 0x46],       type: 'ELF',   ext: '.elf' },
  { bytes: [0x4D, 0x5A],                   type: 'PE/EXE', ext: '.exe' },
  { bytes: [0x1F, 0x8B],                   type: 'GZIP',  ext: '.gz' },
  { bytes: [0x42, 0x4D],                   type: 'BMP',   ext: '.bmp' },
  { bytes: [0x49, 0x44, 0x33],             type: 'MP3',   ext: '.mp3' },
  { bytes: [0x49, 0x49, 0x2A, 0x00],       type: 'TIFF',  ext: '.tif' },
  { bytes: [0x4D, 0x4D, 0x00, 0x2A],       type: 'TIFF',  ext: '.tif' },
  { bytes: [0x52, 0x49, 0x46, 0x46],       type: 'WEBP/AVI', ext: '.webp' },
  { bytes: [0x4F, 0x67, 0x67, 0x53],       type: 'OGG',   ext: '.ogg' },
  { bytes: [0x37, 0x7A, 0xBC, 0xAF],       type: '7ZIP',  ext: '.7z' },
];

// PNG IEND chunk
const PNG_IEND = Buffer.from([0xAE, 0x42, 0x60, 0x82]);
// JPEG EOI marker
const JPEG_EOI = Buffer.from([0xFF, 0xD9]);

export interface FileAnalysisResult {
  path: string;
  detectedType: string;
  declaredExt: string;
  typeMismatch: boolean;
  mismatchWarning?: string;
  strings: string[];
  flagsFound: string[];
  carvedFiles: Array<{ offset: number; type: string; size: number }>;
  exif?: Record<string, unknown>;
  zipContents?: string[];
  notes: string[];
}

// ─── File Carving ─────────────────────────────────────────────────────────────

function carveFiles(buf: Buffer): Array<{ offset: number; type: string; size: number }> {
  const carved: Array<{ offset: number; type: string; size: number }> = [];

  for (let i = 1; i < buf.length - 4; i++) {
    for (const sig of MAGIC_SIGNATURES) {
      if (sig.bytes.every((b, j) => buf[i + j] === b)) {
        // Başlangıç offset'i 0 değilse carved
        const end = Math.min(i + 65536, buf.length);
        carved.push({ offset: i, type: sig.type, size: end - i });
        break;
      }
    }
  }

  // PNG: IEND sonrası veri
  const iendIdx = buf.indexOf(PNG_IEND);
  if (iendIdx !== -1) {
    const afterIend = iendIdx + 4;
    if (afterIend < buf.length) {
      carved.push({ offset: afterIend, type: 'PNG_APPENDED_DATA', size: buf.length - afterIend });
    }
  }

  // JPEG: EOI sonrası veri
  const eoiIdx = buf.lastIndexOf(JPEG_EOI);
  if (eoiIdx !== -1 && eoiIdx + 2 < buf.length) {
    carved.push({ offset: eoiIdx + 2, type: 'JPEG_APPENDED_DATA', size: buf.length - eoiIdx - 2 });
  }

  return carved;
}

// ─── ZIP İçerik Listesi ──────────────────────────────────────────────────────

function listZipContents(buf: Buffer): string[] {
  const files: string[] = [];
  let i = 0;
  while (i < buf.length - 30) {
    // Local file header signature: 50 4B 03 04
    if (buf[i] === 0x50 && buf[i+1] === 0x4B && buf[i+2] === 0x03 && buf[i+3] === 0x04) {
      const flags = buf.readUInt16LE(i + 6);
      const fnLen = buf.readUInt16LE(i + 26);
      const extraLen = buf.readUInt16LE(i + 28);
      const filename = buf.slice(i + 30, i + 30 + fnLen).toString('utf8');
      const isEncrypted = (flags & 0x01) !== 0;
      files.push(isEncrypted ? `${filename} [ŞİFRELİ]` : filename);
      i += 30 + fnLen + extraLen;
    } else {
      i++;
    }
  }
  return files;
}

// ─── EXIF Okuma ──────────────────────────────────────────────────────────────

async function readExif(buf: Buffer): Promise<Record<string, unknown> | undefined> {
  try {
    const { default: exifr } = await import('exifr');
    const data = await exifr.parse(buf, {
      tiff: true, exif: true, gps: true, iptc: true,
      xmp: true, icc: false, jfif: false,
    });
    return data ?? undefined;
  } catch {
    return undefined;
  }
}

// ─── Ana Analiz Fonksiyonu ───────────────────────────────────────────────────

export async function analyzeFile(filePath: string): Promise<FileAnalysisResult> {
  if (!existsSync(filePath)) {
    return {
      path: filePath, detectedType: 'ERROR', declaredExt: '', typeMismatch: false,
      strings: [], flagsFound: [], carvedFiles: [], notes: [`Dosya bulunamadı: ${filePath}`],
    };
  }

  const buf = readFileSync(filePath);
  const declaredExt = extname(filePath).toLowerCase();
  const detectedType = detectMagicType(buf);
  const notes: string[] = [];

  // Uzantı uyuşmazlığı
  const typeExtMap: Record<string, string[]> = {
    JPEG: ['.jpg', '.jpeg'], PNG: ['.png'], GIF: ['.gif'], PDF: ['.pdf'],
    ZIP: ['.zip', '.docx', '.xlsx', '.jar'], ELF: ['.elf', ''], 'PE/EXE': ['.exe'],
  };
  const expectedExts = typeExtMap[detectedType] ?? [];
  const typeMismatch = declaredExt !== '' && expectedExts.length > 0 && !expectedExts.includes(declaredExt);
  const mismatchWarning = typeMismatch
    ? `⚠️  Dikkat: Dosya uzantısı ${declaredExt} ama içerik ${detectedType}`
    : undefined;

  // Strings
  const strings = extractStrings(buf);
  const flagsFound = findFlags(strings);

  // Carving
  const carvedFiles = carveFiles(buf);
  if (carvedFiles.length > 0) {
    notes.push(`📦 ${carvedFiles.length} gizli dosya/veri tespit edildi`);
  }

  // ZIP içeriği
  let zipContents: string[] | undefined;
  if (detectedType === 'ZIP') {
    zipContents = listZipContents(buf);
    const encrypted = zipContents.filter(f => f.includes('[ŞİFRELİ]'));
    if (encrypted.length > 0) notes.push(`🔒 ${encrypted.length} şifreli dosya var`);
  }

  // EXIF
  let exif: Record<string, unknown> | undefined;
  if (detectedType === 'JPEG' || detectedType === 'PNG') {
    exif = await readExif(buf);
    if (exif) {
      // Flag arama - EXIF alanlarında
      const ctfFields = ['Comment', 'UserComment', 'Copyright', 'Artist', 'Software', 'ImageDescription', 'Make', 'Model'];
      for (const field of ctfFields) {
        const val = String(exif[field] ?? '');
        if (/flag\{/i.test(val)) {
          flagsFound.push(val.match(/flag\{[^}]+\}/i)![0]);
          notes.push(`🎯 EXIF ${field} alanında flag bulundu!`);
        }
      }
      if (exif['latitude'] && exif['longitude']) {
        notes.push(`📍 GPS: ${exif['latitude']}, ${exif['longitude']}`);
      }
    }
  }

  // Base64 benzeri uzun string'leri işaretle
  const b64Suspects = strings.filter(s => s.length > 20 && /^[A-Za-z0-9+/]+=*$/.test(s));
  if (b64Suspects.length > 0) notes.push(`🔍 ${b64Suspects.length} adet Base64 benzeri string bulundu`);

  return {
    path: filePath, detectedType, declaredExt, typeMismatch, mismatchWarning,
    strings: strings.slice(0, 50), // İlk 50 string
    flagsFound, carvedFiles, exif, zipContents, notes,
  };
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfFileAnalyzerTool: ToolDefinition = {
  name: 'ctf_file_analyzer',
  description:
    'CTF dosya analizi: magic bytes tespiti, EXIF/metadata okuma, string extraction, ' +
    'file carving (gizli dosya tespiti), ZIP içerik listesi. ' +
    'Dosya path\'i ver, Seth gerçek türünü, gizli verileri ve flag\'leri bulur.',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Analiz edilecek dosyanın tam path\'i' },
    },
    required: ['path'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const filePath = String(input['path'] ?? '').trim();
    if (!filePath) return { output: 'Hata: path boş olamaz.', isError: true };

    const result = await analyzeFile(filePath);
    const lines: string[] = [
      '┌─ DOSYA ANALİZİ ─────────────────────────────────────────────┐',
      `│ Dosya    : ${filePath.slice(-55)}`,
      `│ Gerçek Tür: ${result.detectedType}`,
      `│ Uzantı   : ${result.declaredExt || '(yok)'}`,
    ];
    if (result.mismatchWarning) lines.push(`│ ${result.mismatchWarning}`);
    if (result.flagsFound.length > 0) {
      lines.push(`│ 🎯 FLAG BULUNDU: ${result.flagsFound.join(', ')}`);
    }
    if (result.carvedFiles.length > 0) {
      lines.push(`│ 📦 Gizli Dosyalar:`);
      result.carvedFiles.forEach(c => lines.push(`│   offset=0x${c.offset.toString(16)} tür=${c.type} boyut=${c.size}B`));
    }
    if (result.zipContents) {
      lines.push(`│ 📁 ZIP İçeriği: ${result.zipContents.slice(0, 5).join(', ')}`);
    }
    if (result.notes.length > 0) {
      lines.push('│ Notlar:');
      result.notes.forEach(n => lines.push(`│   ${n}`));
    }
    lines.push('└─────────────────────────────────────────────────────────────┘');

    if (result.strings.length > 0) {
      lines.push('\nÇıkarılan Stringler (ilk 20):');
      result.strings.slice(0, 20).forEach(s => lines.push(`  ${s}`));
    }

    return { output: lines.join('\n') };
  },
};

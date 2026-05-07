/**
 * @fileoverview Fetih CTF Görsel Steganografi — LSB, Alpha, Renk Kanalı, Histogram
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { findFlags, isPrintableAscii } from './ctf-utils.js';

export interface StegoResult {
  method: string;
  found: boolean;
  data: string;
  flagsFound: string[];
  confidence: number;
  notes: string[];
}

export interface StegoAnalysis {
  path: string;
  results: StegoResult[];
  bestResult: StegoResult | null;
  recommendations: string[];
}

// ─── Yardımcılar ─────────────────────────────────────────────────────────────

function bitsToString(bits: number[]): string {
  let result = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    const byte = bits.slice(i, i + 8).reduce((acc, b, j) => acc | (b << (7 - j)), 0);
    if (byte === 0) break; // null terminator
    if (byte >= 32 && byte < 127) result += String.fromCharCode(byte);
    else if (result.length > 4) break; // anlamsız byte geldi, dur
  }
  return result;
}

// isPrintable → isPrintableAscii (ctf-utils'ten import edildi)
const isPrintable = (s: string, threshold = 0.8) => isPrintableAscii(s, threshold);

// ─── Jimp ile Piksel Okuma ───────────────────────────────────────────────────

async function loadPixels(filePath: string): Promise<{
  pixels: Array<{ r: number; g: number; b: number; a: number }>;
  width: number;
  height: number;
} | null> {
  try {
    const jimpModule = await import('jimp');
    const Jimp = jimpModule.default ?? jimpModule;
    const img = await (Jimp as any).read(filePath);
    const width = img.bitmap.width;
    const height = img.bitmap.height;
    const pixels: Array<{ r: number; g: number; b: number; a: number }> = [];
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const idx = (y * width + x) * 4;
        pixels.push({
          r: img.bitmap.data[idx]!,
          g: img.bitmap.data[idx + 1]!,
          b: img.bitmap.data[idx + 2]!,
          a: img.bitmap.data[idx + 3]!,
        });
      }
    }
    return { pixels, width, height };
  } catch {
    return null;
  }
}

// ─── 2.1 LSB Steganografi ────────────────────────────────────────────────────

function extractLSB(
  pixels: Array<{ r: number; g: number; b: number; a: number }>,
  channels: Array<'r' | 'g' | 'b' | 'a'>,
  bits = 1,
  step = 1,
): string {
  const bitArray: number[] = [];
  for (let i = 0; i < pixels.length; i += step) {
    const px = pixels[i]!;
    for (const ch of channels) {
      for (let b = 0; b < bits; b++) {
        bitArray.push((px[ch] >> b) & 1);
      }
    }
  }
  return bitsToString(bitArray);
}

async function lsbAnalysis(filePath: string): Promise<StegoResult[]> {
  const img = await loadPixels(filePath);
  if (!img) return [];

  const results: StegoResult[] = [];
  const variants: Array<{ name: string; channels: Array<'r' | 'g' | 'b' | 'a'>; bits: number; step: number }> = [
    { name: 'LSB-R',      channels: ['r'],              bits: 1, step: 1 },
    { name: 'LSB-RGB',    channels: ['r', 'g', 'b'],    bits: 1, step: 1 },
    { name: 'LSB-RGBA',   channels: ['r', 'g', 'b', 'a'], bits: 1, step: 1 },
    { name: 'LSB-2bit-R', channels: ['r'],              bits: 2, step: 1 },
    { name: 'LSB-step2',  channels: ['r', 'g', 'b'],    bits: 1, step: 2 },
  ];

  for (const v of variants) {
    const data = extractLSB(img.pixels, v.channels, v.bits, v.step);
    const flags = findFlags(data);
    const found = flags.length > 0 || (data.length > 8 && isPrintable(data));
    if (found || flags.length > 0) {
      results.push({
        method: v.name,
        found: true,
        data: data.slice(0, 200),
        flagsFound: flags,
        confidence: flags.length > 0 ? 95 : 60,
        notes: [],
      });
    }
  }
  return results;
}

// ─── 2.4 Alpha Kanal Stego ───────────────────────────────────────────────────

async function alphaAnalysis(filePath: string): Promise<StegoResult | null> {
  const img = await loadPixels(filePath);
  if (!img) return null;

  // Alpha değeri 253 veya 254 olan pikseller şüpheli
  const suspiciousPixels = img.pixels.filter(p => p.a === 253 || p.a === 254);
  const notes: string[] = [];

  if (suspiciousPixels.length > 0) {
    notes.push(`${suspiciousPixels.length} şüpheli alpha piksel (253/254)`);
  }

  // Alpha LSB'lerini topla
  const bits = img.pixels.map(p => p.a & 1);
  const data = bitsToString(bits);
  const flags = findFlags(data);

  if (flags.length > 0 || (data.length > 4 && isPrintable(data))) {
    return {
      method: 'Alpha-LSB',
      found: true,
      data: data.slice(0, 200),
      flagsFound: flags,
      confidence: flags.length > 0 ? 90 : 55,
      notes,
    };
  }
  return suspiciousPixels.length > 10
    ? { method: 'Alpha-LSB', found: false, data: '', flagsFound: [], confidence: 30, notes }
    : null;
}

// ─── 2.5 Renk Kanalı Ayrıştırma ─────────────────────────────────────────────

async function channelAnalysis(filePath: string, outDir: string): Promise<StegoResult[]> {
  const results: StegoResult[] = [];
  try {
    const jimpModule = await import('jimp');
    const Jimp = (jimpModule.default ?? jimpModule) as any;
    const img = await Jimp.read(filePath);
    const w = img.bitmap.width;
    const h = img.bitmap.height;

    for (const [chName, chIdx] of [['R', 0], ['G', 1], ['B', 2]] as Array<[string, number]>) {
      const clone = img.clone();
      for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
          const i = (y * w + x) * 4;
          const val = clone.bitmap.data[i + chIdx]!;
          clone.bitmap.data[i] = val;
          clone.bitmap.data[i + 1] = val;
          clone.bitmap.data[i + 2] = val;
          clone.bitmap.data[i + 3] = 255;
        }
      }
      const outPath = join(outDir, `channel_${chName.toLowerCase()}.png`);
      await clone.write(outPath as `${string}.png`);
      results.push({
        method: `Channel-${chName}`,
        found: true,
        data: `Kaydedildi: ${outPath}`,
        flagsFound: [],
        confidence: 40,
        notes: [`${chName} kanalı ayrıştırıldı → ${outPath}`],
      });
    }
  } catch { /* jimp hatası */ }
  return results;
}

// ─── 2.7 Histogram Anomali ───────────────────────────────────────────────────

async function histogramAnalysis(filePath: string): Promise<StegoResult | null> {
  const img = await loadPixels(filePath);
  if (!img) return null;

  const freq: Record<number, number> = {};
  for (const px of img.pixels) {
    freq[px.r] = (freq[px.r] ?? 0) + 1;
    freq[px.g] = (freq[px.g] ?? 0) + 1;
    freq[px.b] = (freq[px.b] ?? 0) + 1;
  }

  // Belirli değerlerin aşırı tekrarı
  const total = img.pixels.length * 3;
  const anomalies = Object.entries(freq)
    .filter(([, count]) => count / total > 0.05)
    .map(([val, count]) => `değer=${val} (${((count / total) * 100).toFixed(1)}%)`);

  // LSB dağılımı — eşit dağılım stego işareti
  let lsbOnes = 0;
  for (const px of img.pixels) {
    lsbOnes += (px.r & 1) + (px.g & 1) + (px.b & 1);
  }
  const lsbRatio = lsbOnes / (img.pixels.length * 3);
  const lsbAnomaly = Math.abs(lsbRatio - 0.5) < 0.02; // ~%50 → stego şüphesi

  const notes: string[] = [];
  if (lsbAnomaly) notes.push(`⚠️  LSB dağılımı çok dengeli (${(lsbRatio * 100).toFixed(1)}%) → stego şüphesi`);
  if (anomalies.length > 0) notes.push(`Baskın renkler: ${anomalies.slice(0, 3).join(', ')}`);

  if (notes.length > 0) {
    return {
      method: 'Histogram-Analizi',
      found: lsbAnomaly,
      data: notes.join('\n'),
      flagsFound: [],
      confidence: lsbAnomaly ? 65 : 30,
      notes,
    };
  }
  return null;
}

// ─── Ana Stego Analiz Fonksiyonu ─────────────────────────────────────────────

export async function analyzeSteganography(filePath: string): Promise<StegoAnalysis> {
  const recommendations: string[] = [];
  const allResults: StegoResult[] = [];

  if (!existsSync(filePath)) {
    return { path: filePath, results: [], bestResult: null, recommendations: ['Dosya bulunamadı'] };
  }

  // LSB
  const lsbResults = await lsbAnalysis(filePath);
  allResults.push(...lsbResults);

  // Alpha
  const alphaResult = await alphaAnalysis(filePath);
  if (alphaResult) allResults.push(alphaResult);

  // Histogram
  const histResult = await histogramAnalysis(filePath);
  if (histResult) allResults.push(histResult);

  // Kanal ayrıştırma (sadece PNG/BMP için)
  const ext = filePath.toLowerCase();
  if (ext.endsWith('.png') || ext.endsWith('.bmp')) {
    const channelResults = await channelAnalysis(filePath, dirname(filePath));
    allResults.push(...channelResults);
  }

  // Öneriler
  if (!allResults.some(r => r.flagsFound.length > 0)) {
    recommendations.push('zsteg ile daha derin LSB analizi yap: zsteg ' + filePath);
    recommendations.push('stegsolve ile görsel analiz yap');
    recommendations.push('steghide ile şifreli stego ara: steghide extract -sf ' + filePath);
    recommendations.push('binwalk ile gizli dosya ara: binwalk -e ' + filePath);
  }

  // En iyi sonuç
  const withFlags = allResults.filter(r => r.flagsFound.length > 0);
  const bestResult = withFlags.length > 0
    ? withFlags.sort((a, b) => b.confidence - a.confidence)[0]!
    : allResults.sort((a, b) => b.confidence - a.confidence)[0] ?? null;

  return { path: filePath, results: allResults, bestResult, recommendations };
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfStegoTool: ToolDefinition = {
  name: 'ctf_stego',
  description:
    'CTF görsel steganografi analizi: LSB (R/RGB/RGBA/2bit/step), Alpha kanal LSB, ' +
    'renk kanalı ayrıştırma (R/G/B ayrı görüntü), histogram anomali tespiti. ' +
    'PNG/JPEG/BMP dosyalarında gizli veri ve flag arar.',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Analiz edilecek görsel dosyanın tam path\'i' },
    },
    required: ['path'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const filePath = String(input['path'] ?? '').trim();
    if (!filePath) return { output: 'Hata: path boş olamaz.', isError: true };

    const result = await analyzeSteganography(filePath);
    const lines: string[] = [
      '┌─ STEGANOGRAFİ ANALİZİ ──────────────────────────────────────┐',
      `│ Dosya: ${filePath.slice(-55)}`,
      `│ Yöntem Sayısı: ${result.results.length}`,
    ];

    const flagResults = result.results.filter(r => r.flagsFound.length > 0);
    if (flagResults.length > 0) {
      lines.push('│ 🎯 FLAG BULUNDU:');
      flagResults.forEach(r => lines.push(`│   [${r.method}] ${r.flagsFound.join(', ')}`));
    }

    if (result.bestResult) {
      lines.push(`│ En İyi Sonuç: ${result.bestResult.method} (güven: ${result.bestResult.confidence}%)`);
      if (result.bestResult.data) lines.push(`│ Veri: ${result.bestResult.data.slice(0, 60)}`);
    }

    if (result.recommendations.length > 0) {
      lines.push('│ Öneriler:');
      result.recommendations.forEach(r => lines.push(`│   → ${r}`));
    }
    lines.push('└─────────────────────────────────────────────────────────────┘');

    lines.push('\nTüm Sonuçlar:');
    result.results.forEach(r => {
      lines.push(`  [${r.method}] bulundu=${r.found} güven=${r.confidence}% ${r.flagsFound.length > 0 ? '🎯 ' + r.flagsFound.join(',') : ''}`);
      r.notes.forEach(n => lines.push(`    ${n}`));
    });

    return { output: lines.join('\n') };
  },
};

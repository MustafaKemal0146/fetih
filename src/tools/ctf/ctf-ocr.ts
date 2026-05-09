/**
 * @fileoverview Fetih CTF OCR + QR/Barcode Decoder
 * tesseract (OCR) ve zbarimg (QR/barcode) wrapper'ları.
 * Dış araç yoksa image_analyze (VLM) fallback.
 */

import { existsSync } from 'fs';
import { execFileSync } from 'child_process';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { findFlags } from './ctf-utils.js';
import { imageAnalyzeTool } from '../image-analyze.js';

function commandExists(cmd: string): boolean {
  try { execFileSync('which', [cmd], { stdio: 'ignore' }); return true; } catch { return false; }
}

// ─── OCR (tesseract → fallback VLM) ──────────────────────────────────────────

async function runOcr(filePath: string, language = 'eng+tur'): Promise<{ ok: boolean; text: string; source: string; flags: string[] }> {
  if (commandExists('tesseract')) {
    try {
      const out = execFileSync('tesseract', [filePath, '-', '-l', language, '--psm', '6'], {
        encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
      });
      const text = out.trim();
      return { ok: true, text, source: 'tesseract', flags: findFlags(text) };
    } catch (err) {
      // tesseract çalıştı ama dil paketi yok olabilir — eng tek başına dene
      try {
        const out2 = execFileSync('tesseract', [filePath, '-', '-l', 'eng', '--psm', '6'], {
          encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
        });
        const text = out2.trim();
        return { ok: true, text, source: 'tesseract (eng)', flags: findFlags(text) };
      } catch (err2) {
        return { ok: false, text: `tesseract hatası: ${String(err2).slice(0, 200)}`, source: 'tesseract', flags: [] };
      }
    }
  }

  // Fallback: VLM
  try {
    const r = await imageAnalyzeTool.execute({
      path: filePath,
      prompt: 'Bu görseldeki tüm metni AYNEN oku ve düz metin olarak yaz. Yorum yapma, sadece metin.',
    }, process.cwd());
    const text = String(r.output ?? '');
    return {
      ok: !r.isError,
      text,
      source: 'VLM fallback (tesseract yok — sudo apt install tesseract-ocr)',
      flags: findFlags(text),
    };
  } catch (err) {
    return { ok: false, text: `VLM fallback hatası: ${String(err).slice(0, 200)}`, source: 'none', flags: [] };
  }
}

// ─── QR/Barcode (zbarimg → fallback VLM) ─────────────────────────────────────

async function runQrDecode(filePath: string): Promise<{ ok: boolean; text: string; source: string; flags: string[]; codes: string[] }> {
  if (commandExists('zbarimg')) {
    try {
      const out = execFileSync('zbarimg', ['-q', filePath], {
        encoding: 'utf8', timeout: 15_000, maxBuffer: 1024 * 1024,
      });
      const codes = out.trim().split('\n').filter(Boolean);
      const allText = codes.join('\n');
      return { ok: true, text: allText, source: 'zbarimg', flags: findFlags(allText), codes };
    } catch (err) {
      return { ok: false, text: `zbarimg hatası: ${String(err).slice(0, 200)}`, source: 'zbarimg', flags: [], codes: [] };
    }
  }

  // Fallback: VLM
  try {
    const r = await imageAnalyzeTool.execute({
      path: filePath,
      prompt: 'Bu görselde QR kod, barkod veya benzer kodlar var mı? Varsa içeriklerini AYNEN yaz.',
    }, process.cwd());
    const text = String(r.output ?? '');
    return {
      ok: !r.isError,
      text,
      source: 'VLM fallback (zbarimg yok — sudo apt install zbar-tools)',
      flags: findFlags(text),
      codes: [],
    };
  } catch (err) {
    return { ok: false, text: `VLM fallback hatası: ${String(err).slice(0, 200)}`, source: 'none', flags: [], codes: [] };
  }
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfOcrTool: ToolDefinition = {
  name: 'ctf_ocr',
  description:
    'CTF OCR + QR/Barcode okuma. Eylemler: ocr (tesseract → VLM fallback), ' +
    'qr (zbarimg → VLM fallback). ' +
    'Captcha çözme, fotoğraftaki yazı/kod, QR kod fotoğraflar için. ' +
    'Vision LLM\'e göre saniyede çözer, ücretsiz, offline (dış araç kuruluysa).',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['ocr', 'qr'] },
      path: { type: 'string', description: 'Görsel dosyanın tam path\'i' },
      language: { type: 'string', description: 'OCR için dil (varsayılan eng+tur)' },
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

    if (action === 'ocr') {
      const lang = String(input['language'] ?? 'eng+tur');
      const r = await runOcr(filePath, lang);
      const lines = [
        '┌─ OCR ───────────────────────────────────────────────────────┐',
        `│ Kaynak: ${r.source}`,
      ];
      if (r.flags.length > 0) lines.push(`│ 🎯 FLAG: ${r.flags.join(', ')}`);
      lines.push('└─────────────────────────────────────────────────────────────┘', '', r.text);
      return { output: lines.join('\n'), isError: !r.ok };
    }

    if (action === 'qr') {
      const r = await runQrDecode(filePath);
      const lines = [
        '┌─ QR/Barcode ────────────────────────────────────────────────┐',
        `│ Kaynak: ${r.source}`,
        `│ Kod sayısı: ${r.codes.length}`,
      ];
      if (r.flags.length > 0) lines.push(`│ 🎯 FLAG: ${r.flags.join(', ')}`);
      lines.push('└─────────────────────────────────────────────────────────────┘');
      if (r.codes.length > 0) {
        lines.push('', 'Decoded:');
        r.codes.forEach((c, i) => lines.push(`  [${i + 1}] ${c}`));
      } else {
        lines.push('', r.text);
      }
      return { output: lines.join('\n'), isError: !r.ok };
    }

    return { output: `Bilinmeyen eylem: ${action} (ocr veya qr)`, isError: true };
  },
};

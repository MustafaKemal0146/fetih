/**
 * @fileoverview Fetih CTF Otomasyon — Otomatik yönlendirme + paralel analiz + rapor
 */

import { existsSync, readFileSync } from 'fs';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { solve, type SolveResult } from './ctf-solver.js';
import { analyzeWeb, type WebAnalysisResult } from './ctf-web-analyzer.js';
import { analyzeNetwork, type NetworkAnalysisResult } from './ctf-network-analyzer.js';
import { analyzeFile, type FileAnalysisResult } from './ctf-file-analyzer.js';
import { analyzeSteganography, type StegoAnalysis } from './ctf-stego.js';
import { analyzeAudio, type AudioAnalysisReport } from './ctf-audio-analyzer.js';
import { analyzeBinary, type BinaryAnalysisReport } from './ctf-binary-analyzer.js';

// ─── Tipler ──────────────────────────────────────────────────────────────────

export interface AutoReport {
  auto_detected_type: string;
  modules_run: string[];
  total_duration_ms: number;
  solved: boolean;
  flag: string | null;
  confidence: number;
  solver_result?: SolveResult;
  file_result?: FileAnalysisResult;
  stego_result?: StegoAnalysis;
  web_result?: WebAnalysisResult;
  network_result?: NetworkAnalysisResult;
  audio_result?: AudioAnalysisReport;
  binary_result?: BinaryAnalysisReport;
  summary_markdown: string;
}

// ─── 3.1 Input Türü Tespiti ──────────────────────────────────────────────────

type InputType =
  | 'file_image' | 'file_pcap' | 'file_zip' | 'file_pdf' | 'file_audio' | 'file_binary' | 'file_other'
  | 'url_or_http' | 'rsa_params' | 'nmap_output' | 'pcap_text'
  | 'hash' | 'encoding' | 'unknown';

function detectInputType(input: string): InputType {
  const trimmed = input.trim();

  // Dosya path'i mi?
  if ((trimmed.startsWith('/') || /^[A-Za-z]:\\/.test(trimmed)) && existsSync(trimmed)) {
    const buf = readFileSync(trimmed);
    const magic4 = buf.slice(0, 4);
    const head4 = buf.slice(0, 4).toString('ascii');
    const head4to8 = buf.length >= 12 ? buf.slice(8, 12).toString('ascii') : '';
    if (magic4[0] === 0xFF && magic4[1] === 0xD8) return 'file_image';
    if (magic4[0] === 0x89 && magic4[1] === 0x50) return 'file_image'; // PNG
    if (magic4[0] === 0x47 && magic4[1] === 0x49) return 'file_image'; // GIF
    if (magic4[0] === 0xA1 || magic4[0] === 0xD4) return 'file_pcap';
    if (magic4[0] === 0x0A && magic4[1] === 0x0D) return 'file_pcap'; // pcapng
    // Audio: WAV/OGG/FLAC/MP3/M4A
    if (head4 === 'RIFF' && head4to8 === 'WAVE') return 'file_audio';
    if (head4 === 'OggS' || head4 === 'fLaC') return 'file_audio';
    if (head4to8 === 'ftyp') return 'file_audio';
    if (head4.startsWith('ID3') || (magic4[0] === 0xFF && (magic4[1]! & 0xE0) === 0xE0)) return 'file_audio';
    // Binary: ELF / PE
    if (magic4[0] === 0x7F && magic4[1] === 0x45 && magic4[2] === 0x4C && magic4[3] === 0x46) return 'file_binary';
    if (magic4[0] === 0x4D && magic4[1] === 0x5A) return 'file_binary'; // PE/EXE
    if (magic4[0] === 0x50 && magic4[1] === 0x4B) return 'file_zip';
    if (magic4[0] === 0x25 && magic4[1] === 0x50) return 'file_pdf';
    return 'file_other';
  }

  // Hash formatı (length-based hex veya $-prefix)
  if (/^\$[0-9aybs]/i.test(trimmed) && trimmed.length > 10) return 'hash';
  if (/^[0-9a-fA-F]{32,128}$/.test(trimmed) && [32, 40, 56, 64, 96, 128].includes(trimmed.length)) return 'hash';

  // RSA parametreleri
  if (/p\s*=\s*\d+/i.test(trimmed) && /q\s*=\s*\d+/i.test(trimmed)) return 'rsa_params';

  // URL veya HTTP içeriği
  if (/^https?:\/\//i.test(trimmed) || /^(GET|POST|PUT|DELETE)\s+/m.test(trimmed)) return 'url_or_http';
  if (/^[A-Za-z-]+:\s/m.test(trimmed) && trimmed.includes('HTTP/')) return 'url_or_http';

  // Nmap çıktısı
  if (/\d+\/(tcp|udp)\s+open/i.test(trimmed)) return 'nmap_output';

  // PCAP metin çıktısı
  if (/Ethernet|IP \d+\.\d+|TCP \d+\.\d+/.test(trimmed)) return 'pcap_text';

  // Encoding/kripto
  if (/^[A-Za-z0-9+/]+=*$/.test(trimmed.replace(/\s/g, '')) && trimmed.length > 8) return 'encoding';
  if (/^[0-9a-fA-F\s]+$/.test(trimmed) && trimmed.replace(/\s/g, '').length % 2 === 0) return 'encoding';
  if (/^[01\s]+$/.test(trimmed) && trimmed.replace(/\s/g, '').length % 8 === 0) return 'encoding';

  return 'unknown';
}

// ─── 3.2 Paralel Analiz ──────────────────────────────────────────────────────

async function runModules(input: string, inputType: InputType): Promise<{
  modules: string[];
  results: Partial<AutoReport>;
}> {
  const modules: string[] = [];
  const results: Partial<AutoReport> = {};

  switch (inputType) {
    case 'file_image': {
      modules.push('ctf_file_analyzer', 'ctf_stego');
      const [fileRes, stegoRes] = await Promise.all([
        analyzeFile(input),
        analyzeSteganography(input),
      ]);
      results.file_result = fileRes;
      results.stego_result = stegoRes;
      break;
    }

    case 'file_audio': {
      modules.push('ctf_audio_analyzer');
      results.audio_result = await analyzeAudio(input);
      break;
    }

    case 'file_binary': {
      modules.push('ctf_binary_analyzer');
      results.binary_result = await analyzeBinary(input);
      break;
    }

    case 'file_pcap':
    case 'pcap_text': {
      modules.push('ctf_network_analyzer');
      results.network_result = analyzeNetwork(input, inputType === 'file_pcap' ? input : undefined);
      break;
    }

    case 'file_zip':
    case 'file_pdf':
    case 'file_other': {
      modules.push('ctf_file_analyzer');
      results.file_result = await analyzeFile(input);
      break;
    }

    case 'url_or_http': {
      modules.push('ctf_web_analyzer');
      results.web_result = analyzeWeb(input);
      break;
    }

    case 'nmap_output': {
      modules.push('ctf_network_analyzer');
      results.network_result = analyzeNetwork(input);
      break;
    }

    case 'hash': {
      modules.push('ctf_hash');
      const { crackHash } = await import('./ctf-hash.js');
      const hashRes = await crackHash(input);
      // hash sonucunu solver_result formatına yansıt (tek alan üzerinden raporlamak için)
      results.solver_result = {
        flag: hashRes.cracked,
        technique: `Hash crack (${hashRes.format.name})`,
        explanation: hashRes.cracked
          ? `Wordlist eşleşmesi: ${hashRes.attempts} deneme`
          : `Dahili crack başarısız — john/hashcat öner`,
        layers: [],
        confidence: hashRes.cracked ? 100 : 20,
        alternatives: [],
        recommendations: hashRes.externalCommands,
      };
      break;
    }

    case 'rsa_params':
    case 'encoding': {
      modules.push('ctf_solver');
      results.solver_result = solve(input);
      break;
    }

    default: {
      // Belirsiz — paralel çalıştır, en iyi sonucu al
      modules.push('ctf_solver', 'ctf_web_analyzer');
      const [solverRes, webRes] = await Promise.all([
        Promise.resolve(solve(input)),
        Promise.resolve(analyzeWeb(input)),
      ]);
      results.solver_result = solverRes;
      results.web_result = webRes;
      break;
    }
  }

  return { modules, results };
}

// ─── 3.3 Flag ve Confidence Toplama ─────────────────────────────────────────

function extractBestResult(results: Partial<AutoReport>): { flag: string | null; confidence: number } {
  const candidates: Array<{ flag: string; confidence: number }> = [];

  if (results.solver_result?.flag) {
    candidates.push({ flag: results.solver_result.flag, confidence: results.solver_result.confidence });
  }
  if (results.file_result?.flagsFound?.length) {
    candidates.push({ flag: results.file_result.flagsFound[0]!, confidence: 90 });
  }
  if (results.stego_result?.bestResult?.flagsFound?.length) {
    candidates.push({ flag: results.stego_result.bestResult.flagsFound[0]!, confidence: results.stego_result.bestResult.confidence });
  }
  if (results.web_result?.flags_found?.length) {
    candidates.push({ flag: results.web_result.flags_found[0]!, confidence: 85 });
  }
  if (results.network_result?.flags_found?.length) {
    candidates.push({ flag: results.network_result.flags_found[0]!, confidence: 85 });
  }
  if (results.audio_result?.bestFlag) {
    candidates.push({ flag: results.audio_result.bestFlag, confidence: 85 });
  }
  if (results.binary_result?.flagsFound?.length) {
    candidates.push({ flag: results.binary_result.flagsFound[0]!, confidence: 85 });
  }

  if (candidates.length === 0) return { flag: null, confidence: 0 };
  return candidates.sort((a, b) => b.confidence - a.confidence)[0]!;
}

// ─── 3.4 Markdown Rapor ──────────────────────────────────────────────────────

function buildMarkdown(report: AutoReport): string {
  const lines: string[] = [
    '## 🤖 Fetih Otomatik Analiz Raporu',
    `**Input Türü:** ${report.auto_detected_type}`,
    `**Çalışan Modüller:** ${report.modules_run.join(', ')}`,
    `**Süre:** ${report.total_duration_ms}ms`,
    '',
    '### Sonuç',
    report.solved
      ? `✅ **FLAG BULUNDU:** \`${report.flag}\``
      : '❌ Flag bulunamadı',
    `**Güven:** ${report.confidence}/100`,
    '',
    '### Detaylar',
  ];

  if (report.solver_result) {
    lines.push(`**Kripto/Encoding:** ${report.solver_result.technique} (${report.solver_result.layers.length} katman)`);
  }
  if (report.file_result) {
    lines.push(`**Dosya Analizi:** ${report.file_result.detectedType}${report.file_result.typeMismatch ? ' ⚠️ Uzantı uyuşmazlığı' : ''}`);
    if (report.file_result.carvedFiles.length > 0) lines.push(`  - ${report.file_result.carvedFiles.length} gizli dosya tespit edildi`);
  }
  if (report.stego_result) {
    const found = report.stego_result.results.filter(r => r.found).length;
    lines.push(`**Steganografi:** ${found} yöntemde veri bulundu`);
  }
  if (report.web_result) {
    lines.push(`**Web Güvenliği:** ${report.web_result.vulnerabilities_found.length} zafiyet tespit edildi`);
  }
  if (report.network_result) {
    lines.push(`**Network:** ${report.network_result.credentials_found.length} credential, ${report.network_result.open_ports?.length ?? 0} açık port`);
  }

  return lines.join('\n');
}

// ─── Ana Fonksiyon ───────────────────────────────────────────────────────────

export async function autoAnalyze(input: string): Promise<AutoReport> {
  const start = Date.now();
  const inputType = detectInputType(input);
  const { modules, results } = await runModules(input, inputType);
  const { flag, confidence } = extractBestResult(results);

  const report: AutoReport = {
    auto_detected_type: inputType,
    modules_run: modules,
    total_duration_ms: Date.now() - start,
    solved: flag !== null,
    flag,
    confidence,
    ...results,
    summary_markdown: '',
  };

  report.summary_markdown = buildMarkdown(report);
  return report;
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfAutoTool: ToolDefinition = {
  name: 'ctf_auto',
  description:
    'Fetih CTF otomatik analiz motoru. Input türünü otomatik tespit eder ve doğru modülü çalıştırır. ' +
    'Dosya path\'i, URL, şifreli metin, Nmap çıktısı, HTTP header — her şeyi kabul eder. ' +
    'Markdown rapor + flag + güven skoru döndürür.',
  inputSchema: {
    type: 'object',
    properties: {
      input: { type: 'string', description: 'Analiz edilecek veri (dosya path\'i, URL, şifreli metin, vb.)' },
    },
    required: ['input'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(raw: Record<string, unknown>): Promise<ToolResult> {
    const input = String(raw['input'] ?? '').trim();
    if (!input) return { output: 'Hata: input boş olamaz.', isError: true };

    const report = await autoAnalyze(input);

    const lines: string[] = [
      '┌─ FETIH OTOMATİK ANALİZ ──────────────────────────────────────┐',
      `│ Tür: ${report.auto_detected_type.padEnd(20)} Modüller: ${report.modules_run.join(', ').slice(0, 25)}`,
      `│ Süre: ${report.total_duration_ms}ms`,
      '└─────────────────────────────────────────────────────────────┘',
      '',
      report.summary_markdown,
      '',
      JSON.stringify(report, null, 2),
    ];

    return { output: lines.join('\n') };
  },
};

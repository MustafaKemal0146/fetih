/**
 * @fileoverview Fetih CTF Audio Analizi
 * Spektogram görsel okuma (ffmpeg + VLM), WAV LSB steganografi, DTMF tone
 * decode (Goertzel), Morse decoder, ffprobe metadata, magic bytes.
 *
 * Bağımlılıklar (yoksa graceful skip): ffmpeg, ffprobe.
 */

import { existsSync, readFileSync } from 'fs';
import { dirname, join } from 'path';
import { execFileSync } from 'child_process';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { findFlags, isPrintableAscii } from './ctf-utils.js';
import { imageAnalyzeTool } from '../image-analyze.js';

// ─── Tipler ──────────────────────────────────────────────────────────────────

export interface AudioModuleResult {
  module: string;
  ok: boolean;
  data: string;
  flagsFound: string[];
  notes: string[];
}

export interface AudioAnalysisReport {
  path: string;
  detectedFormat: string;
  modules: AudioModuleResult[];
  bestFlag: string | null;
  recommendations: string[];
}

// ─── Magic bytes ─────────────────────────────────────────────────────────────

function detectAudioFormat(buf: Buffer): string {
  if (buf.length < 12) return 'UNKNOWN';
  const head4 = buf.slice(0, 4).toString('ascii');
  const head4to8 = buf.slice(8, 12).toString('ascii');
  if (head4 === 'RIFF' && head4to8 === 'WAVE') return 'WAV';
  if (head4 === 'fLaC') return 'FLAC';
  if (head4 === 'OggS') return 'OGG';
  if (head4.startsWith('ID3') || (buf[0] === 0xFF && (buf[1]! & 0xE0) === 0xE0)) return 'MP3';
  if (head4to8 === 'ftyp') return 'M4A';
  return 'UNKNOWN';
}

function commandExists(cmd: string): boolean {
  try {
    execFileSync('which', [cmd], { stdio: 'ignore' });
    return true;
  } catch { return false; }
}

// ─── WAV header parse ───────────────────────────────────────────────────────

interface WavInfo {
  sampleRate: number;
  bitsPerSample: number;
  channels: number;
  dataOffset: number;
  dataLength: number;
}

function parseWavHeader(buf: Buffer): WavInfo | null {
  // RIFF....WAVEfmt _<chunkSize>...
  if (buf.length < 44 || buf.slice(0, 4).toString() !== 'RIFF' || buf.slice(8, 12).toString() !== 'WAVE') {
    return null;
  }
  // fmt chunk arama
  let offset = 12;
  let info: Partial<WavInfo> = {};
  while (offset < buf.length - 8) {
    const chunkId = buf.slice(offset, offset + 4).toString('ascii');
    const chunkSize = buf.readUInt32LE(offset + 4);
    if (chunkId === 'fmt ') {
      info.channels = buf.readUInt16LE(offset + 10);
      info.sampleRate = buf.readUInt32LE(offset + 12);
      info.bitsPerSample = buf.readUInt16LE(offset + 22);
    } else if (chunkId === 'data') {
      info.dataOffset = offset + 8;
      info.dataLength = chunkSize;
      break;
    }
    offset += 8 + chunkSize + (chunkSize % 2); // word-aligned
  }
  if (info.sampleRate && info.bitsPerSample && info.dataOffset !== undefined) {
    return info as WavInfo;
  }
  return null;
}

// ─── 1. WAV LSB Steganografi ─────────────────────────────────────────────────

function bitsToString(bits: number[]): string {
  let result = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    const byte = bits.slice(i, i + 8).reduce((acc, b, j) => acc | (b << (7 - j)), 0);
    if (byte === 0) break;
    if (byte >= 32 && byte < 127) result += String.fromCharCode(byte);
    else if (result.length > 4) break;
  }
  return result;
}

function wavLsbExtract(buf: Buffer): AudioModuleResult {
  const info = parseWavHeader(buf);
  if (!info) {
    return { module: 'WAV-LSB', ok: false, data: '', flagsFound: [], notes: ['WAV header okunamadı'] };
  }
  const bytesPerSample = info.bitsPerSample / 8;
  const sampleCount = Math.floor(info.dataLength / bytesPerSample);
  const bits: number[] = [];
  // 16-bit samples için little-endian, LSB = en düşük byte'ın bit 0'ı
  for (let i = 0; i < sampleCount; i++) {
    const sampleOffset = info.dataOffset + i * bytesPerSample;
    const lowByte = buf[sampleOffset];
    if (lowByte === undefined) break;
    bits.push(lowByte & 1);
  }
  const text = bitsToString(bits);
  const flags = findFlags(text);
  const notes = [`${sampleCount} sample, ${info.bitsPerSample}-bit, ${info.sampleRate} Hz, ${info.channels} kanal`];
  return {
    module: 'WAV-LSB',
    ok: flags.length > 0 || (text.length > 8 && isPrintableAscii(text)),
    data: text.slice(0, 200),
    flagsFound: flags,
    notes,
  };
}

// ─── 2. DTMF Tone Decoder (Goertzel) ─────────────────────────────────────────

const DTMF_LOW = [697, 770, 852, 941];
const DTMF_HIGH = [1209, 1336, 1477, 1633];
const DTMF_KEYS = [
  ['1', '2', '3', 'A'],
  ['4', '5', '6', 'B'],
  ['7', '8', '9', 'C'],
  ['*', '0', '#', 'D'],
];

function goertzelMagnitude(samples: Float32Array, freq: number, sampleRate: number): number {
  const n = samples.length;
  const k = Math.round((n * freq) / sampleRate);
  const omega = (2 * Math.PI * k) / n;
  const coeff = 2 * Math.cos(omega);
  let q1 = 0, q2 = 0;
  for (let i = 0; i < n; i++) {
    const q0 = coeff * q1 - q2 + (samples[i] ?? 0);
    q2 = q1;
    q1 = q0;
  }
  return Math.sqrt(q1 * q1 + q2 * q2 - q1 * q2 * coeff);
}

function dtmfDecode(buf: Buffer): AudioModuleResult {
  const info = parseWavHeader(buf);
  if (!info || info.bitsPerSample !== 16) {
    return { module: 'DTMF', ok: false, data: '', flagsFound: [], notes: ['DTMF için 16-bit WAV gerekli'] };
  }
  const sampleCount = Math.floor(info.dataLength / 2);
  // Mono assume — stereo ise sadece L kanalı
  const channels = info.channels;
  const stride = channels * 2;
  const monoSamples = new Float32Array(sampleCount / channels);
  for (let i = 0; i < monoSamples.length; i++) {
    const offset = info.dataOffset + i * stride;
    if (offset + 1 >= buf.length) break;
    monoSamples[i] = buf.readInt16LE(offset) / 32768;
  }

  // 30 ms pencere ile sürekli tarama, eşik aşıldığında tuş ekle, art arda tekrarı bastır
  const winSize = Math.floor(info.sampleRate * 0.03);
  const decoded: string[] = [];
  let lastKey = '';
  let lastChangeIdx = -winSize;

  for (let start = 0; start + winSize <= monoSamples.length; start += winSize) {
    const window = monoSamples.slice(start, start + winSize);
    const lowMags = DTMF_LOW.map(f => goertzelMagnitude(window, f, info.sampleRate));
    const highMags = DTMF_HIGH.map(f => goertzelMagnitude(window, f, info.sampleRate));
    const lowMax = Math.max(...lowMags);
    const highMax = Math.max(...highMags);
    const lowIdx = lowMags.indexOf(lowMax);
    const highIdx = highMags.indexOf(highMax);

    // Sinyal eşiği — sessizlik ayrımı
    const threshold = 5;
    if (lowMax > threshold && highMax > threshold) {
      const key = DTMF_KEYS[lowIdx]?.[highIdx] ?? '';
      if (key && (key !== lastKey || start - lastChangeIdx > winSize * 3)) {
        decoded.push(key);
        lastKey = key;
        lastChangeIdx = start;
      }
    } else {
      lastKey = '';
    }
  }

  const text = decoded.join('');
  return {
    module: 'DTMF',
    ok: text.length > 0,
    data: text,
    flagsFound: findFlags(text),
    notes: text.length > 0 ? [`${decoded.length} tuş tespit edildi`] : ['DTMF tonu bulunamadı'],
  };
}

// ─── 3. Morse Decoder (amplitude-based) ──────────────────────────────────────

const MORSE_TABLE: Record<string, string> = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
  '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
  '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
  '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
  '-.--': 'Y', '--..': 'Z',
  '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
  '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
};

function morseDecode(buf: Buffer): AudioModuleResult {
  const info = parseWavHeader(buf);
  if (!info || info.bitsPerSample !== 16) {
    return { module: 'Morse', ok: false, data: '', flagsFound: [], notes: ['Morse için 16-bit WAV gerekli'] };
  }
  const channels = info.channels;
  const stride = channels * 2;
  const sampleCount = Math.floor(info.dataLength / stride);

  // RMS amplitude — pencereli
  const winSize = Math.floor(info.sampleRate * 0.01); // 10 ms
  const states: number[] = []; // 1 = sinyal var, 0 = sessizlik
  let maxRms = 0;
  const rmsValues: number[] = [];

  for (let start = 0; start + winSize <= sampleCount; start += winSize) {
    let sumSq = 0;
    for (let i = 0; i < winSize; i++) {
      const off = info.dataOffset + (start + i) * stride;
      if (off + 1 >= buf.length) break;
      const s = buf.readInt16LE(off) / 32768;
      sumSq += s * s;
    }
    const rms = Math.sqrt(sumSq / winSize);
    rmsValues.push(rms);
    if (rms > maxRms) maxRms = rms;
  }

  if (maxRms < 0.01) {
    return { module: 'Morse', ok: false, data: '', flagsFound: [], notes: ['Sinyal eşiğinin altında'] };
  }
  const threshold = maxRms * 0.3;
  for (const rms of rmsValues) states.push(rms > threshold ? 1 : 0);

  // Run-length encoding: ardışık aynı state grupları
  const runs: Array<{ state: number; len: number }> = [];
  let cur = states[0] ?? 0, len = 1;
  for (let i = 1; i < states.length; i++) {
    if (states[i] === cur) len++;
    else { runs.push({ state: cur, len }); cur = states[i]!; len = 1; }
  }
  runs.push({ state: cur, len });

  // Dot ve dash ayırma — sinyal run'larının uzunluk medyanını bul, dot ~1x, dash ~3x
  const sigRuns = runs.filter(r => r.state === 1).map(r => r.len);
  if (sigRuns.length === 0) {
    return { module: 'Morse', ok: false, data: '', flagsFound: [], notes: ['Sinyal aralığı bulunamadı'] };
  }
  sigRuns.sort((a, b) => a - b);
  const minSig = sigRuns[0]!;
  const dotMax = minSig * 2; // 1x ile 3x arası ayrım

  // Mesajı oluştur
  let morse = '';
  for (const run of runs) {
    if (run.state === 1) {
      morse += run.len <= dotMax ? '.' : '-';
    } else {
      // Sessizlik: short=içsembol(boş), medium=harf arası( ), long=kelime arası(/)
      if (run.len <= dotMax) morse += '';
      else if (run.len <= dotMax * 3) morse += ' ';
      else morse += ' / ';
    }
  }

  // Decode
  const words = morse.split('/').map(w => w.trim());
  const decoded = words.map(word =>
    word.split(/\s+/).map(letter => MORSE_TABLE[letter] ?? '').join(''),
  ).join(' ');

  const ok = decoded.length > 0 && /[A-Z0-9]/.test(decoded);
  return {
    module: 'Morse',
    ok,
    data: decoded,
    flagsFound: findFlags(decoded.toLowerCase()),
    notes: ok ? [`Morse: ${morse.slice(0, 80)}`] : ['Tanınabilir Morse pattern bulunamadı'],
  };
}

// ─── 4. ffprobe metadata ─────────────────────────────────────────────────────

function ffprobeMetadata(filePath: string): AudioModuleResult {
  if (!commandExists('ffprobe')) {
    return { module: 'Metadata', ok: false, data: '', flagsFound: [], notes: ['ffprobe yok (sudo apt install ffmpeg)'] };
  }
  try {
    const out = execFileSync('ffprobe', [
      '-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', filePath,
    ], { encoding: 'utf8', timeout: 10_000 });
    const flags = findFlags(out);
    return {
      module: 'Metadata',
      ok: true,
      data: out.slice(0, 800),
      flagsFound: flags,
      notes: flags.length > 0 ? ['Metadata\'da flag bulundu'] : [],
    };
  } catch (err) {
    return { module: 'Metadata', ok: false, data: '', flagsFound: [], notes: [`ffprobe hatası: ${String(err).slice(0, 100)}`] };
  }
}

// ─── 5. Spektogram + Vision ──────────────────────────────────────────────────

async function spectrogramVision(filePath: string): Promise<AudioModuleResult> {
  if (!commandExists('ffmpeg')) {
    return { module: 'Spektogram-Vision', ok: false, data: '', flagsFound: [], notes: ['ffmpeg yok (sudo apt install ffmpeg)'] };
  }
  const dir = dirname(filePath);
  const specPath = join(dir, `_fetih_spec_${Date.now()}.png`);
  try {
    execFileSync('ffmpeg', [
      '-y', '-i', filePath, '-lavfi', 'showspectrumpic=s=1024x512:legend=disabled',
      specPath,
    ], { stdio: 'ignore', timeout: 30_000 });
  } catch (err) {
    return { module: 'Spektogram-Vision', ok: false, data: '', flagsFound: [], notes: [`ffmpeg hatası: ${String(err).slice(0, 100)}`] };
  }

  if (!existsSync(specPath)) {
    return { module: 'Spektogram-Vision', ok: false, data: '', flagsFound: [], notes: ['Spektogram üretilemedi'] };
  }

  // Vision tool çağrısı
  try {
    const visionResult = await imageAnalyzeTool.execute({
      path: specPath,
      prompt:
        'Bu bir ses dosyasının spektogramı. Görselde herhangi bir okunabilir METİN ' +
        '(harf, rakam, flag{...} formatı), Morse benzeri DAHA-NOKTA pattern, veya ' +
        'gizlenmiş bir mesaj görüyor musun? Sadece tespit ettiklerini yaz, yorum yapma.',
    }, dir);
    const text = String(visionResult.output ?? '');
    const flags = findFlags(text);
    return {
      module: 'Spektogram-Vision',
      ok: !visionResult.isError,
      data: text.slice(0, 600),
      flagsFound: flags,
      notes: [`Spektogram: ${specPath}`],
    };
  } catch (err) {
    return { module: 'Spektogram-Vision', ok: false, data: '', flagsFound: [], notes: [`Vision hatası: ${String(err).slice(0, 100)}`] };
  }
}

// ─── Ana Analiz ──────────────────────────────────────────────────────────────

export async function analyzeAudio(filePath: string): Promise<AudioAnalysisReport> {
  if (!existsSync(filePath)) {
    return {
      path: filePath, detectedFormat: 'ERROR', modules: [],
      bestFlag: null, recommendations: [`Dosya bulunamadı: ${filePath}`],
    };
  }
  const buf = readFileSync(filePath);
  const detectedFormat = detectAudioFormat(buf);
  const modules: AudioModuleResult[] = [];

  // Metadata her tip için çalışır
  modules.push(ffprobeMetadata(filePath));

  // WAV-spesifik
  if (detectedFormat === 'WAV') {
    modules.push(wavLsbExtract(buf));
    modules.push(dtmfDecode(buf));
    modules.push(morseDecode(buf));
  }

  // Spektogram (ffmpeg her tipi okuyabilir)
  modules.push(await spectrogramVision(filePath));

  const allFlags = modules.flatMap(m => m.flagsFound);
  const bestFlag = allFlags[0] ?? null;
  const recommendations: string[] = [];
  if (!bestFlag) {
    recommendations.push('Audacity ile manuel inceleme: spektogram, frekans analizi, ters çalma');
    recommendations.push('sonic-visualiser ile melody/spektogram detay');
    if (detectedFormat === 'WAV') recommendations.push('steghide extract -sf <file> deneyin');
  }

  return { path: filePath, detectedFormat, modules, bestFlag, recommendations };
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfAudioAnalyzerTool: ToolDefinition = {
  name: 'ctf_audio_analyzer',
  description:
    'CTF ses dosyası analizi: WAV LSB steganografi, DTMF tone decode (Goertzel), ' +
    'Morse code decoder, ffprobe metadata, ffmpeg spektogram + vision LLM ile ' +
    'spektogramda metin/morse tespiti. WAV/MP3/FLAC/OGG/M4A destekler.',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Analiz edilecek ses dosyasının tam path\'i' },
    },
    required: ['path'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const filePath = String(input['path'] ?? '').trim();
    if (!filePath) return { output: 'Hata: path boş olamaz.', isError: true };

    const r = await analyzeAudio(filePath);

    const lines: string[] = [
      '┌─ AUDIO ANALİZİ ─────────────────────────────────────────────┐',
      `│ Dosya  : ${filePath.slice(-55)}`,
      `│ Format : ${r.detectedFormat}`,
    ];
    if (r.bestFlag) lines.push(`│ 🎯 FLAG: ${r.bestFlag}`);
    lines.push('└─────────────────────────────────────────────────────────────┘');

    for (const m of r.modules) {
      const status = m.ok ? '✓' : '✗';
      const flagPart = m.flagsFound.length > 0 ? ` 🎯 ${m.flagsFound.join(',')}` : '';
      lines.push(`\n[${status}] ${m.module}${flagPart}`);
      if (m.data) lines.push(`    ${m.data.split('\n').join('\n    ').slice(0, 400)}`);
      m.notes.forEach(n => lines.push(`    ${n}`));
    }

    if (r.recommendations.length > 0) {
      lines.push('\nÖneriler:');
      r.recommendations.forEach(rec => lines.push(`  → ${rec}`));
    }

    return { output: lines.join('\n'), isError: false };
  },
};

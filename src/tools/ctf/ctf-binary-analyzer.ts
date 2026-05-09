/**
 * @fileoverview Fetih CTF Binary Analizi (Reverse Engineering)
 * file/strings/xxd/objdump/readelf/nm/binwalk wrapper'ları + heuristic vuln tespiti.
 * Statik analiz: ELF/PE header, semboller, format string, RWX segment, basit ROP gadget.
 */

import { existsSync, readFileSync } from 'fs';
import { execFileSync } from 'child_process';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { findFlags } from './ctf-utils.js';

export interface BinarySection {
  module: string;
  ok: boolean;
  output: string;
  notes: string[];
}

export interface BinaryAnalysisReport {
  path: string;
  fileType: string;
  sections: BinarySection[];
  flagsFound: string[];
  securityIndicators: string[];
  suggestedNext: string[];
}

function commandExists(cmd: string): boolean {
  try {
    execFileSync('which', [cmd], { stdio: 'ignore' });
    return true;
  } catch { return false; }
}

function safeRun(cmd: string, args: string[], maxBytes = 16_000): { ok: boolean; output: string; error?: string } {
  try {
    const out = execFileSync(cmd, args, {
      encoding: 'utf8',
      timeout: 20_000,
      maxBuffer: 4 * 1024 * 1024,
    });
    return { ok: true, output: out.length > maxBytes ? out.slice(0, maxBytes) + '\n…[kırpıldı]' : out };
  } catch (err) {
    return { ok: false, output: '', error: String(err).slice(0, 200) };
  }
}

// ─── Modüller ────────────────────────────────────────────────────────────────

function fileTypeSection(filePath: string): BinarySection {
  if (!commandExists('file')) {
    return { module: 'file', ok: false, output: '', notes: ['file komutu yok'] };
  }
  const r = safeRun('file', ['-b', filePath], 500);
  return { module: 'file', ok: r.ok, output: r.output.trim(), notes: r.error ? [r.error] : [] };
}

function stringsSection(filePath: string): { section: BinarySection; flags: string[] } {
  if (!commandExists('strings')) {
    return { section: { module: 'strings', ok: false, output: '', notes: ['strings yok'] }, flags: [] };
  }
  const r = safeRun('strings', ['-a', '-n', '5', filePath], 50_000);
  const flags = findFlags(r.output);
  // İlginç kelime arama
  const interesting = r.output.split('\n').filter(line =>
    /flag|ctf|secret|password|key|admin|backdoor|TODO|FIXME|http:\/\/|https:\/\//i.test(line),
  ).slice(0, 30);
  const display = interesting.length > 0 ? interesting.join('\n') : r.output.split('\n').slice(0, 50).join('\n');
  return {
    section: {
      module: 'strings',
      ok: r.ok,
      output: display.slice(0, 4000),
      notes: flags.length > 0 ? [`🎯 ${flags.length} flag bulundu`] : interesting.length > 0 ? [`${interesting.length} ilginç string`] : [],
    },
    flags,
  };
}

function xxdSection(filePath: string): BinarySection {
  if (!commandExists('xxd')) {
    return { module: 'xxd', ok: false, output: '', notes: ['xxd yok'] };
  }
  const r = safeRun('xxd', ['-l', '256', filePath], 4000);
  return { module: 'xxd (ilk 256 byte)', ok: r.ok, output: r.output, notes: [] };
}

function readelfSection(filePath: string): { section: BinarySection; security: string[] } {
  if (!commandExists('readelf')) {
    return { section: { module: 'readelf', ok: false, output: '', notes: ['readelf yok'] }, security: [] };
  }
  const r = safeRun('readelf', ['-h', '-l', filePath], 6000);
  const security: string[] = [];
  // RWX segment tespiti: program header'da Flags "RWE" pattern'i
  if (/\bRWE\b/.test(r.output)) {
    security.push('⚠️  RWX segment tespit edildi (executable + writable) — shellcode uygun');
  }
  // NX-bit yok: GNU_STACK RW (E olmadan)
  if (/GNU_STACK[^\n]*\bRWE\b/.test(r.output)) {
    security.push('⚠️  NX-bit pasif (GNU_STACK executable)');
  } else if (/GNU_STACK[^\n]*\bRW\b/.test(r.output)) {
    security.push('✓ NX-bit aktif (GNU_STACK non-executable)');
  }
  // Stripped/PIE
  if (/Type:\s+EXEC/.test(r.output)) security.push('Type: EXEC — non-PIE (statik adresler)');
  if (/Type:\s+DYN/.test(r.output)) security.push('Type: DYN — PIE veya shared lib (ASLR)');
  return { section: { module: 'readelf -h -l', ok: r.ok, output: r.output, notes: [] }, security };
}

function nmSection(filePath: string): BinarySection {
  if (!commandExists('nm')) {
    return { module: 'nm', ok: false, output: '', notes: ['nm yok'] };
  }
  const r = safeRun('nm', ['--demangle', filePath], 8000);
  // İlginç sembol arama
  const interesting = r.output.split('\n').filter(line =>
    /\b(main|flag|secret|password|admin|backdoor|debug|hidden|key)\b/i.test(line),
  ).slice(0, 30);
  const display = interesting.length > 0
    ? `İlginç semboller:\n${interesting.join('\n')}`
    : r.output.split('\n').slice(0, 30).join('\n');
  return {
    module: 'nm',
    ok: r.ok,
    output: display.slice(0, 3000),
    notes: interesting.length > 0 ? [`${interesting.length} ilginç sembol`] : [],
  };
}

function objdumpSection(filePath: string): { section: BinarySection; security: string[] } {
  if (!commandExists('objdump')) {
    return { section: { module: 'objdump', ok: false, output: '', notes: ['objdump yok'] }, security: [] };
  }
  // Sadece text section disassembly (tüm dosyayı disassemble etmek çok uzun)
  const r = safeRun('objdump', ['-d', '--no-show-raw-insn', '-M', 'intel', filePath], 30_000);
  const security: string[] = [];

  // Format string vuln heuristik: printf/fprintf çağrılarına önce push edilen format arg
  if (/call\s+[0-9a-f]+\s*<printf@plt>/i.test(r.output)) {
    security.push('printf@plt çağrısı var — format string vuln için %s/%n/%x payload\'ları test edilebilir');
  }
  // Tehlikeli fonksiyonlar
  const dangerous = ['gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'system'];
  for (const fn of dangerous) {
    const re = new RegExp(`<${fn}@plt>`);
    if (re.test(r.output)) security.push(`⚠️  ${fn}@plt — buffer overflow / komut enjeksiyonu vektörü`);
  }
  // Basit ROP gadget arama: "pop ...; ret" pattern'i
  const gadgets = (r.output.match(/^[ \t]+[0-9a-f]+:\s+pop\s+\w+\s*\n[ \t]+[0-9a-f]+:\s+ret\b/gm) ?? []).slice(0, 5);
  if (gadgets.length > 0) {
    security.push(`🔧 ${gadgets.length}+ basit "pop reg; ret" gadget tespit edildi (ROP için kullanılabilir)`);
  }
  return { section: { module: 'objdump -d', ok: r.ok, output: r.output.slice(0, 3000) + (r.output.length > 3000 ? '\n…[truncated]' : ''), notes: [] }, security };
}

function binwalkSection(filePath: string): { section: BinarySection; flags: string[] } {
  if (!commandExists('binwalk')) {
    return { section: { module: 'binwalk', ok: false, output: '', notes: ['binwalk yok (sudo apt install binwalk)'] }, flags: [] };
  }
  const r = safeRun('binwalk', [filePath], 4000);
  const flags = findFlags(r.output);
  return { section: { module: 'binwalk', ok: r.ok, output: r.output.slice(0, 2000), notes: [] }, flags };
}

// ─── Ana Analiz ──────────────────────────────────────────────────────────────

export async function analyzeBinary(filePath: string): Promise<BinaryAnalysisReport> {
  if (!existsSync(filePath)) {
    return {
      path: filePath, fileType: 'ERROR', sections: [],
      flagsFound: [], securityIndicators: [`Dosya bulunamadı: ${filePath}`], suggestedNext: [],
    };
  }

  const sections: BinarySection[] = [];
  const flagsFound: string[] = [];
  const securityIndicators: string[] = [];
  const suggestedNext: string[] = [];

  // 1. file
  const fileSec = fileTypeSection(filePath);
  sections.push(fileSec);
  const fileType = fileSec.output || 'UNKNOWN';

  // ELF mi PE mi tespit
  const buf = readFileSync(filePath, { encoding: null });
  const isELF = buf.length >= 4 && buf[0] === 0x7F && buf[1] === 0x45 && buf[2] === 0x4C && buf[3] === 0x46;
  const isPE = buf.length >= 2 && buf[0] === 0x4D && buf[1] === 0x5A;

  // 2. xxd
  sections.push(xxdSection(filePath));

  // 3. strings (her binary için)
  const stringsRes = stringsSection(filePath);
  sections.push(stringsRes.section);
  flagsFound.push(...stringsRes.flags);

  // 4. ELF spesifik
  if (isELF) {
    const elfRes = readelfSection(filePath);
    sections.push(elfRes.section);
    securityIndicators.push(...elfRes.security);
    sections.push(nmSection(filePath));
    const objdumpRes = objdumpSection(filePath);
    sections.push(objdumpRes.section);
    securityIndicators.push(...objdumpRes.security);
    suggestedNext.push(
      'gdb dynamic analysis: gdb -q ' + filePath,
      'pwntools template: from pwn import *; ELF("' + filePath + '")',
      'radare2: r2 -A ' + filePath,
      'Ghidra: import dosya, decompile main',
    );
  } else if (isPE) {
    suggestedNext.push(
      'PE analiz için: pefile (Python), CFF Explorer, Ghidra',
      'IDA Pro veya Binary Ninja ile decompile',
    );
  }

  // 5. binwalk (her tip için faydalı)
  const binwalkRes = binwalkSection(filePath);
  sections.push(binwalkRes.section);
  flagsFound.push(...binwalkRes.flags);

  return {
    path: filePath,
    fileType,
    sections,
    flagsFound: [...new Set(flagsFound)],
    securityIndicators,
    suggestedNext,
  };
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfBinaryAnalyzerTool: ToolDefinition = {
  name: 'ctf_binary_analyzer',
  description:
    'CTF binary/RE analizi: file/strings/xxd/readelf/nm/objdump/binwalk wrapper. ' +
    'ELF/PE tespit, RWX/NX/PIE bilgisi, ilginç semboller, tehlikeli fonksiyon (gets/strcpy/printf) ' +
    'tespiti, basit ROP gadget arama, gömülü dosya tespiti. ' +
    'Statik analiz; gdb/radare2/Ghidra önerisi de döner.',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Analiz edilecek binary dosyasının tam path\'i' },
    },
    required: ['path'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const filePath = String(input['path'] ?? '').trim();
    if (!filePath) return { output: 'Hata: path boş olamaz.', isError: true };

    const r = await analyzeBinary(filePath);

    const lines: string[] = [
      '┌─ BİNARY ANALİZİ ────────────────────────────────────────────┐',
      `│ Dosya  : ${filePath.slice(-55)}`,
      `│ Tip    : ${r.fileType.slice(0, 60)}`,
    ];
    if (r.flagsFound.length > 0) lines.push(`│ 🎯 FLAG: ${r.flagsFound.join(', ')}`);
    lines.push('└─────────────────────────────────────────────────────────────┘');

    if (r.securityIndicators.length > 0) {
      lines.push('\n🔐 Güvenlik Göstergeleri:');
      r.securityIndicators.forEach(s => lines.push(`  ${s}`));
    }

    for (const sec of r.sections) {
      lines.push(`\n[${sec.ok ? '✓' : '✗'}] ${sec.module}`);
      if (sec.output) lines.push(sec.output);
      sec.notes.forEach(n => lines.push(`  ${n}`));
    }

    if (r.suggestedNext.length > 0) {
      lines.push('\n💡 Sonraki Adım Önerileri:');
      r.suggestedNext.forEach(s => lines.push(`  → ${s}`));
    }

    return { output: lines.join('\n'), isError: false };
  },
};

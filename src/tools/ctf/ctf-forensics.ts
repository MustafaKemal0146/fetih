/**
 * @fileoverview Fetih CTF Forensics — PCAP binary parse, memory dump (volatility wrapper),
 * file recovery (foremost wrapper), büyük dosya strings sweep.
 */

import { existsSync, readFileSync, statSync, openSync, readSync, closeSync } from 'fs';
import { execFileSync } from 'child_process';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { findFlags, extractStrings } from './ctf-utils.js';

function commandExists(cmd: string): boolean {
  try { execFileSync('which', [cmd], { stdio: 'ignore' }); return true; } catch { return false; }
}

// ─── 1. PCAP Binary Parse ────────────────────────────────────────────────────

export interface PcapPacket {
  index: number;
  ts: number;
  capLen: number;
  origLen: number;
  // Layer 2/3 highlights (best-effort)
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  protocol?: string;
  payloadPreview?: string;
}

export interface PcapSummary {
  ok: boolean;
  format: 'pcap' | 'pcapng' | 'unknown';
  byteOrder: 'le' | 'be';
  linkType?: number;
  packets: PcapPacket[];
  totalPackets: number;
  uniqueIps: string[];
  protocols: Record<string, number>;
  httpRequests: string[];
  flagsFound: string[];
  notes: string[];
}

export function parsePcap(buf: Buffer, maxPackets = 100): PcapSummary {
  const result: PcapSummary = {
    ok: false, format: 'unknown', byteOrder: 'le',
    packets: [], totalPackets: 0, uniqueIps: [], protocols: {},
    httpRequests: [], flagsFound: [], notes: [],
  };
  if (buf.length < 24) {
    result.notes.push('PCAP header için yetersiz boyut');
    return result;
  }
  // Magic
  const magic = buf.readUInt32BE(0);
  let isLe = false;
  if (magic === 0xA1B2C3D4) { isLe = false; result.format = 'pcap'; result.byteOrder = 'be'; }
  else if (magic === 0xD4C3B2A1) { isLe = true; result.format = 'pcap'; result.byteOrder = 'le'; }
  else if (magic === 0x0A0D0D0A) { result.format = 'pcapng'; result.notes.push('PCAPNG formatı — basit parser sadece pcap destekler. tshark öneriliyor.'); return result; }
  else { result.notes.push(`Bilinmeyen magic: 0x${magic.toString(16)}`); return result; }

  result.linkType = isLe ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
  // Sadece Ethernet (LinkType=1) destekliyoruz
  if (result.linkType !== 1) {
    result.notes.push(`LinkType ${result.linkType} — sadece Ethernet (1) destekleniyor`);
    return result;
  }

  const ipsSeen = new Set<string>();
  const protoCount: Record<string, number> = {};
  let offset = 24;
  let pktIdx = 0;

  while (offset < buf.length - 16 && pktIdx < maxPackets) {
    const ts = isLe ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
    const capLen = isLe ? buf.readUInt32LE(offset + 8) : buf.readUInt32BE(offset + 8);
    const origLen = isLe ? buf.readUInt32LE(offset + 12) : buf.readUInt32BE(offset + 12);
    const dataOffset = offset + 16;

    if (capLen <= 0 || capLen > 65535 || dataOffset + capLen > buf.length) break;

    const data = buf.slice(dataOffset, dataOffset + capLen);
    const pkt: PcapPacket = { index: pktIdx, ts, capLen, origLen };

    // Ethernet header (14 bytes): dst[6], src[6], ethertype[2]
    if (data.length >= 14) {
      const ethertype = data.readUInt16BE(12);
      // IPv4 = 0x0800
      if (ethertype === 0x0800 && data.length >= 14 + 20) {
        const ipHeader = data.slice(14);
        const ihl = (ipHeader[0]! & 0x0F) * 4;
        const proto = ipHeader[9]!;
        pkt.srcIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
        pkt.dstIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
        ipsSeen.add(pkt.srcIp); ipsSeen.add(pkt.dstIp);
        const protoName = proto === 6 ? 'TCP' : proto === 17 ? 'UDP' : proto === 1 ? 'ICMP' : `IP/${proto}`;
        pkt.protocol = protoName;
        protoCount[protoName] = (protoCount[protoName] ?? 0) + 1;

        if ((proto === 6 || proto === 17) && ipHeader.length >= ihl + 8) {
          const transport = ipHeader.slice(ihl);
          pkt.srcPort = transport.readUInt16BE(0);
          pkt.dstPort = transport.readUInt16BE(2);
          // TCP payload başlangıcı
          if (proto === 6 && transport.length >= 20) {
            const dataOff = (transport[12]! >> 4) * 4;
            const payload = transport.slice(dataOff);
            if (payload.length > 0) {
              const text = payload.toString('utf8').slice(0, 200);
              pkt.payloadPreview = text;
              const httpMatch = text.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)/);
              if (httpMatch) result.httpRequests.push(`${httpMatch[1]} ${httpMatch[2]}`);
            }
          }
        }
      }
    }

    result.packets.push(pkt);
    offset = dataOffset + capLen;
    pktIdx++;
  }

  // Kalan paketleri sayar (parse etmeden)
  let totalCount = pktIdx;
  let countOffset = offset;
  while (countOffset < buf.length - 16) {
    const capLen = isLe ? buf.readUInt32LE(countOffset + 8) : buf.readUInt32BE(countOffset + 8);
    if (capLen <= 0 || capLen > 65535 || countOffset + 16 + capLen > buf.length) break;
    countOffset += 16 + capLen;
    totalCount++;
  }
  result.totalPackets = totalCount;

  // Tüm buffer'da flag ara (basit string scan)
  result.flagsFound = findFlags(extractStrings(buf, 6));
  result.uniqueIps = [...ipsSeen].slice(0, 30);
  result.protocols = protoCount;
  result.ok = true;
  return result;
}

// ─── 2. Volatility Wrapper (memory dump) ────────────────────────────────────

export function volatilityRun(filePath: string, plugin: string): { ok: boolean; output: string; tool: string; notes: string[] } {
  const tools = ['vol3', 'vol.py', 'volatility3', 'volatility'];
  const tool = tools.find(t => commandExists(t));
  if (!tool) {
    return {
      ok: false, output: '', tool: 'none',
      notes: [
        'Volatility kurulu değil',
        'Kurulum: pip install volatility3',
        '   veya: sudo apt install volatility',
        '',
        `Plugin önerileri (${plugin}):`,
        '  windows.pslist.PsList   → process listesi',
        '  windows.cmdline.CmdLine → komut satırı',
        '  windows.filescan.FileScan → dosya cache',
        '  linux.bash.Bash         → bash history',
        '  linux.pslist.PsList     → linux processes',
      ],
    };
  }

  try {
    const args = tool.includes('3') || tool === 'vol.py' || tool === 'vol3'
      ? ['-f', filePath, plugin]
      : ['-f', filePath, plugin]; // hem v2 hem v3 benzer
    const out = execFileSync(tool, args, { encoding: 'utf8', timeout: 120_000, maxBuffer: 16 * 1024 * 1024 });
    const flags = findFlags(out);
    const notes = flags.length > 0 ? [`🎯 ${flags.length} flag bulundu: ${flags.join(', ')}`] : [];
    return { ok: true, output: out.slice(0, 16_000), tool, notes };
  } catch (err) {
    return { ok: false, output: '', tool, notes: [`${tool} hatası: ${String(err).slice(0, 200)}`] };
  }
}

// ─── 3. Foremost / Binwalk File Recovery ────────────────────────────────────

export function foremostRun(filePath: string, outputDir: string): { ok: boolean; output: string; tool: string; notes: string[] } {
  if (commandExists('foremost')) {
    try {
      const out = execFileSync('foremost', ['-i', filePath, '-o', outputDir, '-q'], {
        encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024,
      });
      return { ok: true, output: out.slice(0, 4000), tool: 'foremost', notes: [`Çıktı dizini: ${outputDir}`] };
    } catch (err) {
      return { ok: false, output: '', tool: 'foremost', notes: [`foremost hatası: ${String(err).slice(0, 200)}`] };
    }
  }
  if (commandExists('binwalk')) {
    try {
      const out = execFileSync('binwalk', ['-e', '--directory', outputDir, filePath], {
        encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024,
      });
      return { ok: true, output: out.slice(0, 4000), tool: 'binwalk', notes: [`Çıktı dizini: ${outputDir}`] };
    } catch (err) {
      return { ok: false, output: '', tool: 'binwalk', notes: [`binwalk hatası: ${String(err).slice(0, 200)}`] };
    }
  }
  return {
    ok: false, output: '', tool: 'none',
    notes: ['Ne foremost ne binwalk kurulu', 'Kurulum: sudo apt install foremost binwalk'],
  };
}

// ─── 4. Büyük Dosya Strings Sweep (chunked, RAM bounded) ────────────────────

export function largeFileStringsSweep(filePath: string, chunkSize = 1 * 1024 * 1024, maxFlags = 50): { flags: string[]; bytesScanned: number; notes: string[] } {
  if (!existsSync(filePath)) return { flags: [], bytesScanned: 0, notes: ['Dosya yok'] };
  const fileSize = statSync(filePath).size;
  const flags: string[] = [];
  const fd = openSync(filePath, 'r');
  let pos = 0;
  let totalScanned = 0;
  const chunk = Buffer.alloc(chunkSize + 64); // overlap için biraz fazla

  try {
    let prevTail = Buffer.alloc(0);
    while (pos < fileSize && flags.length < maxFlags) {
      const bytesRead = readSync(fd, chunk, 0, chunkSize, pos);
      if (bytesRead === 0) break;
      const combined = Buffer.concat([prevTail, chunk.slice(0, bytesRead)]);
      const strings = extractStrings(combined, 6);
      const found = findFlags(strings);
      for (const f of found) {
        if (!flags.includes(f) && flags.length < maxFlags) flags.push(f);
      }
      // Son 64 byte'ı sonraki chunk için tut (kesilen string'ler için)
      prevTail = combined.slice(-64);
      pos += bytesRead;
      totalScanned += bytesRead;
    }
  } finally {
    closeSync(fd);
  }

  return {
    flags,
    bytesScanned: totalScanned,
    notes: [
      `Taranan: ${(totalScanned / 1024 / 1024).toFixed(1)} MB`,
      `Toplam dosya: ${(fileSize / 1024 / 1024).toFixed(1)} MB`,
    ],
  };
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfForensicsTool: ToolDefinition = {
  name: 'ctf_forensics',
  description:
    'CTF Forensics: pcap_parse (binary PCAP parse — paket sayım, IP/port, HTTP, flag sweep), ' +
    'volatility (memory dump analizi — vol3/vol2 wrapper), file_recovery (foremost/binwalk wrapper), ' +
    'strings_sweep (büyük dosyalarda chunked flag arama). ' +
    'Memory dump, network capture, disk image challenge\'ları için.',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['pcap_parse', 'volatility', 'file_recovery', 'strings_sweep'] },
      path: { type: 'string', description: 'Hedef dosyanın tam path\'i' },
      plugin: { type: 'string', description: 'Volatility plugin (örn. windows.pslist.PsList)' },
      outputDir: { type: 'string', description: 'file_recovery çıktı dizini' },
      maxPackets: { type: 'number', description: 'pcap_parse için detaylı parse edilecek paket sayısı (varsayılan 100)' },
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

    switch (action) {
      case 'pcap_parse': {
        const buf = readFileSync(filePath);
        const max = Number(input['maxPackets'] ?? 100);
        const r = parsePcap(buf, max);
        const lines = [
          '┌─ PCAP PARSE ────────────────────────────────────────────────┐',
          `│ Format       : ${r.format} (${r.byteOrder})`,
          `│ LinkType     : ${r.linkType}`,
          `│ Toplam paket : ${r.totalPackets} (parse: ${r.packets.length})`,
          `│ Benzersiz IP : ${r.uniqueIps.length}`,
          `│ Protokoller  : ${Object.entries(r.protocols).map(([p, c]) => `${p}:${c}`).join(', ')}`,
          `│ HTTP istek   : ${r.httpRequests.length}`,
        ];
        if (r.flagsFound.length > 0) lines.push(`│ 🎯 FLAG: ${r.flagsFound.join(', ')}`);
        lines.push('└─────────────────────────────────────────────────────────────┘');

        if (r.httpRequests.length > 0) {
          lines.push('\nHTTP Requests (ilk 20):');
          r.httpRequests.slice(0, 20).forEach((h, i) => lines.push(`  [${i + 1}] ${h}`));
        }
        if (r.uniqueIps.length > 0) {
          lines.push('\nIP\'ler:');
          lines.push('  ' + r.uniqueIps.slice(0, 15).join(', '));
        }
        if (r.notes.length > 0) {
          lines.push('\nNotlar:');
          r.notes.forEach(n => lines.push(`  ${n}`));
        }
        return { output: lines.join('\n'), isError: !r.ok };
      }

      case 'volatility': {
        const plugin = String(input['plugin'] ?? 'windows.pslist.PsList');
        const r = volatilityRun(filePath, plugin);
        const lines = [
          `┌─ VOLATILITY (${r.tool}) ────────────────────────────────────┐`,
          `│ Plugin: ${plugin}`,
          '└─────────────────────────────────────────────────────────────┘',
        ];
        if (r.output) lines.push(r.output);
        if (r.notes.length > 0) lines.push('\n' + r.notes.join('\n'));
        return { output: lines.join('\n'), isError: !r.ok };
      }

      case 'file_recovery': {
        const outputDir = String(input['outputDir'] ?? `/tmp/fetih_recovery_${Date.now()}`);
        const r = foremostRun(filePath, outputDir);
        const lines = [
          `┌─ FILE RECOVERY (${r.tool}) ─────────────────────────────────┐`,
          '└─────────────────────────────────────────────────────────────┘',
        ];
        if (r.output) lines.push(r.output);
        if (r.notes.length > 0) lines.push('\n' + r.notes.join('\n'));
        return { output: lines.join('\n'), isError: !r.ok };
      }

      case 'strings_sweep': {
        const r = largeFileStringsSweep(filePath);
        const lines = [
          '┌─ STRINGS SWEEP (büyük dosya, chunked) ──────────────────────┐',
          ...r.notes.map(n => `│ ${n}`),
        ];
        if (r.flags.length > 0) {
          lines.push(`│ 🎯 ${r.flags.length} flag bulundu`);
          lines.push('└─────────────────────────────────────────────────────────────┘', '', ...r.flags.map((f, i) => `  [${i + 1}] ${f}`));
        } else {
          lines.push('│ ✗ Flag bulunamadı', '└─────────────────────────────────────────────────────────────┘');
        }
        return { output: lines.join('\n'), isError: false };
      }

      default:
        return { output: `Bilinmeyen eylem: ${action}`, isError: true };
    }
  },
};

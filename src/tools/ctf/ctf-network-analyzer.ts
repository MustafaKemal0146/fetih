/**
 * @fileoverview Seth CTF Network Analizi
 * PCAP analizi, HTTP header kontrolü, port tarama çıktısı analizi
 */

import { readFileSync, existsSync } from 'fs';
import type { ToolDefinition, ToolResult } from '../../types.js';

export interface PortDetail {
  port: number;
  protocol: string;
  service: string;
  version?: string;
  attack_vectors: string[];
}

export interface NetworkAnalysisResult {
  pcap_summary?: {
    total_packets: number;
    protocols: Record<string, number>;
    unique_ips: string[];
    http_requests: Array<{ method: string; url: string; body?: string }>;
  };
  credentials_found: string[];
  files_extracted: string[];
  http_headers?: {
    missing_security: string[];
    sensitive_info: string[];
    flags_in_headers: string[];
  };
  open_ports?: PortDetail[];
  flags_found: string[];
  recommendations: string[];
}

// ─── 2.1 PCAP Analizi ────────────────────────────────────────────────────────

const PCAP_MAGIC = Buffer.from([0xA1, 0xB2, 0xC3, 0xD4]);
const PCAP_MAGIC_LE = Buffer.from([0xD4, 0xC3, 0xB2, 0xA1]);
const PCAPNG_MAGIC = Buffer.from([0x0A, 0x0D, 0x0D, 0x0A]);

function isPcap(buf: Buffer): boolean {
  return buf.slice(0, 4).equals(PCAP_MAGIC) ||
    buf.slice(0, 4).equals(PCAP_MAGIC_LE) ||
    buf.slice(0, 4).equals(PCAPNG_MAGIC);
}

function analyzePcapText(content: string): NetworkAnalysisResult['pcap_summary'] {
  // tshark veya tcpdump metin çıktısını parse et
  const protocols: Record<string, number> = {};
  const ips = new Set<string>();
  const httpRequests: Array<{ method: string; url: string; body?: string }> = [];

  const lines = content.split('\n');
  for (const line of lines) {
    // Protokol tespiti
    for (const proto of ['HTTP', 'DNS', 'FTP', 'SMTP', 'TCP', 'UDP', 'TLS', 'SSH', 'Telnet']) {
      if (line.includes(proto)) protocols[proto] = (protocols[proto] ?? 0) + 1;
    }

    // IP adresleri
    const ipMatches = line.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
    for (const m of ipMatches) ips.add(m[1]!);

    // HTTP istekleri
    const httpMatch = line.match(/(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(https?:\/\/[^\s]+|\/[^\s]*)/);
    if (httpMatch) {
      httpRequests.push({ method: httpMatch[1]!, url: httpMatch[2]! });
    }
  }

  return {
    total_packets: lines.length,
    protocols,
    unique_ips: [...ips].slice(0, 20),
    http_requests: httpRequests.slice(0, 20),
  };
}

function findCredentials(content: string): string[] {
  const creds: string[] = [];

  // HTTP Basic Auth: Authorization: Basic <base64>
  const basicAuthMatches = content.matchAll(/Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/gi);
  for (const m of basicAuthMatches) {
    try {
      const decoded = Buffer.from(m[1]!, 'base64').toString('utf8');
      if (decoded.includes(':')) creds.push(`HTTP Basic Auth: ${decoded}`);
    } catch { /* ignore */ }
  }

  // FTP credentials
  const ftpUser = content.match(/USER\s+(\S+)/i);
  const ftpPass = content.match(/PASS\s+(\S+)/i);
  if (ftpUser) creds.push(`FTP User: ${ftpUser[1]}`);
  if (ftpPass) creds.push(`FTP Pass: ${ftpPass[1]}`);

  // SMTP AUTH
  const smtpAuth = content.matchAll(/AUTH LOGIN\s*\n([A-Za-z0-9+/=]+)\s*\n([A-Za-z0-9+/=]+)/gi);
  for (const m of smtpAuth) {
    try {
      const user = Buffer.from(m[1]!, 'base64').toString();
      const pass = Buffer.from(m[2]!, 'base64').toString();
      creds.push(`SMTP: ${user}:${pass}`);
    } catch { /* ignore */ }
  }

  // Telnet/cleartext password patterns
  const passPatterns = content.matchAll(/(?:password|passwd|pwd)\s*[=:]\s*(\S+)/gi);
  for (const m of passPatterns) {
    creds.push(`Cleartext password: ${m[1]}`);
  }

  return [...new Set(creds)];
}

function findDnsFlags(content: string): string[] {
  const flags: string[] = [];
  // DNS TXT record'da flag
  const dnsMatches = content.matchAll(/TXT\s+"([^"]+)"/g);
  for (const m of dnsMatches) {
    if (/flag\{/i.test(m[1]!)) flags.push(m[1]!);
  }
  // Base64 DNS exfil
  const b64Dns = content.matchAll(/([A-Za-z0-9+/]{20,}==?)\s*\./g);
  for (const m of b64Dns) {
    try {
      const decoded = Buffer.from(m[1]!, 'base64').toString();
      if (/flag\{/i.test(decoded)) flags.push(decoded);
    } catch { /* ignore */ }
  }
  return flags;
}

// ─── 2.2 HTTP Header Analizi ─────────────────────────────────────────────────

const REQUIRED_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
];

const SENSITIVE_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];

function analyzeHttpHeaders(headerText: string): NetworkAnalysisResult['http_headers'] {
  const headers: Record<string, string> = {};
  const flagsInHeaders: string[] = [];

  for (const line of headerText.split('\n')) {
    const idx = line.indexOf(':');
    if (idx > 0) {
      const key = line.slice(0, idx).trim().toLowerCase();
      const val = line.slice(idx + 1).trim();
      headers[key] = val;

      // Flag arama
      if (/flag\{[^}]+\}/i.test(val)) {
        flagsInHeaders.push(`${key}: ${val.match(/flag\{[^}]+\}/i)![0]}`);
      }
      // Custom header'larda flag
      if (/^x-(?:flag|secret|ctf|key|token)/i.test(key)) {
        flagsInHeaders.push(`${key}: ${val}`);
      }
    }
  }

  const missing = REQUIRED_HEADERS.filter(h => !(h in headers));
  const sensitive = SENSITIVE_HEADERS
    .filter(h => h in headers)
    .map(h => `${h}: ${headers[h]}`);

  // Cookie analizi
  const setCookie = headers['set-cookie'] ?? '';
  if (setCookie && !setCookie.includes('HttpOnly')) {
    sensitive.push('Set-Cookie: HttpOnly flag eksik');
  }
  if (setCookie && !setCookie.includes('Secure')) {
    sensitive.push('Set-Cookie: Secure flag eksik');
  }
  if (/flag\{/i.test(setCookie)) {
    flagsInHeaders.push(`Set-Cookie flag: ${setCookie.match(/flag\{[^}]+\}/i)![0]}`);
  }

  return { missing_security: missing, sensitive_info: sensitive, flags_in_headers: flagsInHeaders };
}

// ─── 2.3 Port Tarama Analizi ─────────────────────────────────────────────────

const PORT_ATTACK_VECTORS: Record<number, { service: string; attacks: string[] }> = {
  21:   { service: 'FTP',        attacks: ['anonymous login dene: ftp <ip>', 'hydra -l anonymous -p "" ftp://<ip>'] },
  22:   { service: 'SSH',        attacks: ['ssh root@<ip>', 'hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<ip>'] },
  23:   { service: 'Telnet',     attacks: ['telnet <ip>', 'cleartext protokol — sniff et'] },
  25:   { service: 'SMTP',       attacks: ['nc <ip> 25', 'VRFY root', 'EXPN admin'] },
  53:   { service: 'DNS',        attacks: ['dig axfr @<ip> domain.com', 'dnsrecon -d domain.com -t axfr'] },
  80:   { service: 'HTTP',       attacks: ['gobuster dir -u http://<ip>', 'nikto -h http://<ip>'] },
  443:  { service: 'HTTPS',      attacks: ['gobuster dir -u https://<ip>', 'sslscan <ip>'] },
  445:  { service: 'SMB',        attacks: ['smbclient -L //<ip>', 'enum4linux <ip>'] },
  3306: { service: 'MySQL',      attacks: ["mysql -h <ip> -u root -p''", 'hydra -l root -P rockyou.txt mysql://<ip>'] },
  5432: { service: 'PostgreSQL', attacks: ['psql -h <ip> -U postgres', 'hydra -l postgres -P rockyou.txt postgres://<ip>'] },
  6379: { service: 'Redis',      attacks: ['redis-cli -h <ip>', 'redis-cli -h <ip> CONFIG GET *'] },
  8080: { service: 'HTTP-Alt',   attacks: ['gobuster dir -u http://<ip>:8080', 'curl http://<ip>:8080/manager/html'] },
  27017:{ service: 'MongoDB',    attacks: ['mongo <ip>', 'mongodump --host <ip>'] },
};

function parseNmapOutput(content: string): PortDetail[] {
  const ports: PortDetail[] = [];
  const portLines = content.matchAll(/(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?/g);

  for (const m of portLines) {
    const port = Number(m[1]);
    const protocol = m[2]!;
    const service = m[3]!;
    const version = m[4]?.trim();
    const known = PORT_ATTACK_VECTORS[port];

    ports.push({
      port,
      protocol,
      service: known?.service ?? service,
      version,
      attack_vectors: known?.attacks.map(a => a.replace(/<ip>/g, 'TARGET')) ?? [],
    });
  }

  return ports;
}

// ─── Ana Analiz Fonksiyonu ───────────────────────────────────────────────────

export function analyzeNetwork(input: string, filePath?: string): NetworkAnalysisResult {
  const result: NetworkAnalysisResult = {
    credentials_found: [],
    files_extracted: [],
    flags_found: [],
    recommendations: [],
  };

  // Dosya analizi
  if (filePath && existsSync(filePath)) {
    const buf = readFileSync(filePath);
    if (isPcap(buf)) {
      result.recommendations.push(`PCAP dosyası tespit edildi. tshark ile analiz et:`);
      result.recommendations.push(`tshark -r "${filePath}" -Y "http" -T fields -e http.request.method -e http.request.uri`);
      result.recommendations.push(`tshark -r "${filePath}" -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg`);
      result.recommendations.push(`tshark -r "${filePath}" -z "conv,tcp" -q`);
    }
  }

  // Metin içeriği analizi
  const creds = findCredentials(input);
  result.credentials_found.push(...creds);

  const dnsFlags = findDnsFlags(input);
  result.flags_found.push(...dnsFlags);

  // Flag arama — genel
  const generalFlags = input.match(/flag\{[^}]+\}/gi) ?? [];
  result.flags_found.push(...generalFlags);

  // HTTP header analizi
  if (/^[A-Za-z-]+:\s/m.test(input)) {
    const hdrs = analyzeHttpHeaders(input);
    result.http_headers = hdrs;
    if (hdrs) result.flags_found.push(...hdrs.flags_in_headers);
  }

  // Nmap çıktısı analizi
  if (/\d+\/(tcp|udp)\s+open/i.test(input)) {
    result.open_ports = parseNmapOutput(input);
    if (result.open_ports.length > 0) {
      result.recommendations.push(`${result.open_ports.length} açık port tespit edildi`);
      for (const p of result.open_ports.slice(0, 5)) {
        result.recommendations.push(`Port ${p.port} (${p.service}): ${p.attack_vectors[0] ?? 'manuel inceleme'}`);
      }
    }
  }

  // PCAP metin çıktısı (tshark/tcpdump)
  if (input.includes('Ethernet') || input.includes('IP ') || /\d+\.\d+\.\d+\.\d+\s*->\s*\d+/.test(input)) {
    result.pcap_summary = analyzePcapText(input);
  }

  // Genel öneriler
  if (result.credentials_found.length > 0) {
    result.recommendations.push(`⚠️  ${result.credentials_found.length} kimlik bilgisi tespit edildi!`);
  }
  if (result.flags_found.length === 0) {
    result.recommendations.push('Wireshark ile TCP stream\'leri takip et: Follow → TCP Stream');
    result.recommendations.push('Base64 string ara: strings capture.pcap | grep -E "^[A-Za-z0-9+/]{20,}={0,2}$"');
  }

  result.flags_found = [...new Set(result.flags_found)];
  return result;
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfNetworkAnalyzerTool: ToolDefinition = {
  name: 'ctf_network_analyzer',
  description:
    'CTF network analizi: PCAP dosyası, HTTP header, Nmap çıktısı analizi. ' +
    'Credential tespiti (Basic Auth, FTP, SMTP), flag arama, port saldırı vektörleri. ' +
    'Dosya path\'i veya metin içeriği ver.',
  inputSchema: {
    type: 'object',
    properties: {
      input: { type: 'string', description: 'Nmap çıktısı, HTTP header\'ları veya PCAP metin çıktısı' },
      file_path: { type: 'string', description: 'PCAP dosyasının path\'i (opsiyonel)' },
    },
    required: ['input'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(raw: Record<string, unknown>): Promise<ToolResult> {
    const input = String(raw['input'] ?? '').trim();
    const filePath = raw['file_path'] ? String(raw['file_path']) : undefined;
    if (!input && !filePath) return { output: 'Hata: input veya file_path gerekli.', isError: true };

    const result = analyzeNetwork(input || '', filePath);
    const lines: string[] = [
      '┌─ NETWORK ANALİZİ ───────────────────────────────────────────┐',
      `│ Credential: ${result.credentials_found.length} | Port: ${result.open_ports?.length ?? 0} | Flag: ${result.flags_found.length}`,
      '└─────────────────────────────────────────────────────────────┘',
    ];

    if (result.flags_found.length > 0) lines.push(`\n🎯 FLAG: ${result.flags_found.join(', ')}`);
    if (result.credentials_found.length > 0) {
      lines.push('\n🔑 Kimlik Bilgileri:');
      result.credentials_found.forEach(c => lines.push(`  ${c}`));
    }
    if (result.open_ports && result.open_ports.length > 0) {
      lines.push('\n🔌 Açık Portlar:');
      result.open_ports.forEach(p => {
        lines.push(`  ${p.port}/${p.protocol} ${p.service}${p.version ? ` (${p.version})` : ''}`);
        p.attack_vectors.slice(0, 1).forEach(a => lines.push(`    → ${a}`));
      });
    }
    if (result.http_headers) {
      if (result.http_headers.missing_security.length > 0)
        lines.push(`\n⚠️  Eksik Header: ${result.http_headers.missing_security.join(', ')}`);
      if (result.http_headers.sensitive_info.length > 0)
        lines.push(`\n⚠️  Hassas Bilgi: ${result.http_headers.sensitive_info.join(', ')}`);
      if (result.http_headers.flags_in_headers.length > 0)
        lines.push(`\n🎯 Header Flag: ${result.http_headers.flags_in_headers.join(', ')}`);
    }
    if (result.recommendations.length > 0) {
      lines.push('\n📋 Öneriler:');
      result.recommendations.slice(0, 6).forEach(r => lines.push(`  → ${r}`));
    }

    lines.push('\n' + JSON.stringify(result, null, 2));
    return { output: lines.join('\n') };
  },
};

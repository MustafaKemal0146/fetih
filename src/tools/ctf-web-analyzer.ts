/**
 * @fileoverview Seth CTF Web Güvenliği Analizi
 * SQLi, XSS, LFI, IDOR tespiti + dizin keşfi önerileri
 */

import type { ToolDefinition, ToolResult } from '../types.js';

export interface VulnDetail {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  parameter?: string;
  evidence: string;
  payloads: string[];
  tool_command?: string;
}

export interface WebAnalysisResult {
  target: string;
  vulnerabilities_found: VulnDetail[];
  recommendations: string[];
  tools_suggested: string[];
  flags_found: string[];
}

// ─── 1.1 SQLi Tespiti ────────────────────────────────────────────────────────

const SQLI_ERROR_PATTERNS = [
  /syntax error/i, /mysql_fetch/i, /ORA-\d+/i, /SQLite/i,
  /pg_query/i, /mssql/i, /Unclosed quotation/i, /quoted string not properly terminated/i,
  /You have an error in your SQL syntax/i, /Warning.*mysql/i,
];

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "' AND 1=1--",
  "' AND 1=2--",
  "' AND SLEEP(5)--",
  "' UNION SELECT NULL--",
  "' AND 1=CONVERT(int, @@version)--",
];

function detectSQLi(input: string, params: Record<string, string>): VulnDetail[] {
  const vulns: VulnDetail[] = [];

  // Response'ta SQL hata mesajı var mı?
  const hasError = SQLI_ERROR_PATTERNS.some(p => p.test(input));
  if (hasError) {
    const match = SQLI_ERROR_PATTERNS.find(p => p.test(input));
    vulns.push({
      type: 'SQL Injection (Error-Based)',
      severity: 'critical',
      evidence: `SQL hata mesajı tespit edildi: ${match}`,
      payloads: SQLI_PAYLOADS,
      tool_command: `sqlmap -u "${Object.keys(params)[0] ?? 'URL'}" --dbs --batch`,
    });
  }

  // Sayısal parametre var mı?
  for (const [key, val] of Object.entries(params)) {
    if (/^\d+$/.test(val)) {
      vulns.push({
        type: 'SQL Injection (Potansiyel)',
        severity: 'high',
        parameter: key,
        evidence: `Sayısal parametre: ${key}=${val}`,
        payloads: SQLI_PAYLOADS,
        tool_command: `sqlmap -u "URL" -p "${key}" --dbs --batch`,
      });
    }
    // Tek tırnak içeren parametre
    if (val.includes("'")) {
      vulns.push({
        type: 'SQL Injection (Tırnak Testi)',
        severity: 'high',
        parameter: key,
        evidence: `Parametre tek tırnak içeriyor: ${key}`,
        payloads: SQLI_PAYLOADS,
        tool_command: `sqlmap -u "URL" -p "${key}" --level=3 --batch`,
      });
    }
  }

  return vulns;
}

// ─── 1.2 XSS Tespiti ─────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  '"><svg onload=alert(1)>',
  "'><script>alert(document.domain)</script>",
];

function detectXSS(input: string, headers: Record<string, string>, params: Record<string, string>): VulnDetail[] {
  const vulns: VulnDetail[] = [];

  const contentType = headers['content-type'] ?? headers['Content-Type'] ?? '';
  const isHtml = contentType.includes('text/html') || input.includes('<html') || input.includes('<!DOCTYPE');
  const hasXssProtection = 'x-xss-protection' in headers || 'X-XSS-Protection' in headers;
  const hasCSP = 'content-security-policy' in headers || 'Content-Security-Policy' in headers;

  // Input değeri response'ta yansıyor mu?
  for (const [key, val] of Object.entries(params)) {
    if (val.length > 2 && input.includes(val) && isHtml) {
      vulns.push({
        type: 'Reflected XSS',
        severity: 'high',
        parameter: key,
        evidence: `Parametre değeri (${val}) response'ta yansıyor`,
        payloads: XSS_PAYLOADS,
        tool_command: `dalfox url "URL?${key}=FUZZ" --mining-dom`,
      });
    }
  }

  // Güvenlik header eksikliği
  if (isHtml && !hasXssProtection && !hasCSP) {
    vulns.push({
      type: 'XSS Koruma Eksikliği',
      severity: 'medium',
      evidence: 'X-XSS-Protection ve CSP header eksik',
      payloads: XSS_PAYLOADS,
    });
  }

  // Script injection pattern
  if (/<script|onerror=|onload=|javascript:/i.test(input)) {
    vulns.push({
      type: 'XSS (Stored/DOM Şüphesi)',
      severity: 'high',
      evidence: 'Response\'ta script/event handler içeriği var',
      payloads: XSS_PAYLOADS,
    });
  }

  return vulns;
}

// ─── 1.3 LFI Tespiti ─────────────────────────────────────────────────────────

const LFI_PARAMS = ['file', 'page', 'path', 'include', 'template', 'view', 'doc', 'load'];
const LFI_PAYLOADS = [
  '../../../../etc/passwd',
  '....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '/proc/self/environ',
  'php://filter/convert.base64-encode/resource=index.php',
  'C:\\Windows\\win.ini',
  '../../../../windows/win.ini',
];
const LFI_LINUX_FILES = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/self/environ', '/var/log/apache2/access.log'];
const LFI_WINDOWS_FILES = ['C:\\Windows\\win.ini', 'C:\\boot.ini', 'C:\\Windows\\System32\\drivers\\etc\\hosts'];

function detectLFI(url: string, params: Record<string, string>): VulnDetail[] {
  const vulns: VulnDetail[] = [];

  for (const [key, val] of Object.entries(params)) {
    if (LFI_PARAMS.includes(key.toLowerCase())) {
      const isLinux = !url.includes('C:') && !val.includes('\\');
      vulns.push({
        type: 'LFI / Path Traversal',
        severity: 'critical',
        parameter: key,
        evidence: `LFI'ya açık parametre: ${key}=${val}`,
        payloads: LFI_PAYLOADS,
        tool_command: `ffuf -u "URL?${key}=FUZZ" -w /usr/share/wordlists/lfi.txt`,
      });
      vulns[vulns.length - 1]!.payloads.push(
        ...(isLinux ? LFI_LINUX_FILES : LFI_WINDOWS_FILES)
      );
    }
  }

  // Response'ta /etc/passwd içeriği var mı?
  if (/root:x:0:0|daemon:x:|bin:x:/.test(url)) {
    vulns.push({
      type: 'LFI (Başarılı)',
      severity: 'critical',
      evidence: '/etc/passwd içeriği response\'ta tespit edildi',
      payloads: LFI_PAYLOADS,
    });
  }

  return vulns;
}

// ─── 1.4 IDOR Tespiti ────────────────────────────────────────────────────────

function detectIDOR(url: string, params: Record<string, string>): VulnDetail[] {
  const vulns: VulnDetail[] = [];

  // URL'de numeric ID
  const urlIdMatch = url.match(/\/(\d+)(?:\/|$|\?)/);
  if (urlIdMatch) {
    const id = Number(urlIdMatch[1]);
    vulns.push({
      type: 'IDOR (URL)',
      severity: 'high',
      evidence: `URL'de numeric ID: ${urlIdMatch[1]}`,
      payloads: [`${id - 1}`, `${id + 1}`, '0', '-1', '99999', '1'],
      tool_command: `ffuf -u "${url.replace(urlIdMatch[1]!, 'FUZZ')}" -w numbers.txt`,
    });
  }

  // Parametre'de numeric ID
  for (const [key, val] of Object.entries(params)) {
    if (/^(id|user_id|uid|account|profile|order)$/i.test(key) && /^\d+$/.test(val)) {
      const id = Number(val);
      vulns.push({
        type: 'IDOR (Parametre)',
        severity: 'high',
        parameter: key,
        evidence: `Numeric ID parametresi: ${key}=${val}`,
        payloads: [`${id - 1}`, `${id + 1}`, '0', '-1', '99999'],
      });
    }
  }

  return vulns;
}

// ─── 1.5 Dizin Keşfi ─────────────────────────────────────────────────────────

const CRITICAL_PATHS = [
  '/robots.txt', '/sitemap.xml', '/.git/config', '/.env',
  '/admin', '/admin.php', '/backup.zip', '/wp-config.php',
  '/config.php', '/phpinfo.php', '/.htaccess', '/web.config',
  '/.git/HEAD', '/api/v1/', '/swagger.json', '/api-docs',
];

function directoryDiscovery(baseUrl: string): { paths: string[]; commands: string[] } {
  const cleanUrl = baseUrl.replace(/\/$/, '');
  return {
    paths: CRITICAL_PATHS.map(p => cleanUrl + p),
    commands: [
      `gobuster dir -u "${cleanUrl}" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,zip`,
      `ffuf -u "${cleanUrl}/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403`,
      `curl -s "${cleanUrl}/robots.txt"`,
      `curl -s "${cleanUrl}/.git/config"`,
    ],
  };
}

// ─── URL/Parametre Ayrıştırma ─────────────────────────────────────────────────

function parseUrlAndParams(input: string): { url: string; params: Record<string, string>; headers: Record<string, string> } {
  const params: Record<string, string> = {};
  const headers: Record<string, string> = {};
  let url = '';

  // URL tespiti
  const urlMatch = input.match(/https?:\/\/[^\s"']+/);
  if (urlMatch) {
    url = urlMatch[0]!;
    try {
      const u = new URL(url);
      u.searchParams.forEach((v, k) => { params[k] = v; });
    } catch { /* ignore */ }
  }

  // HTTP header satırları
  const headerLines = input.split('\n').filter(l => /^[A-Za-z-]+:\s/.test(l));
  for (const line of headerLines) {
    const idx = line.indexOf(':');
    if (idx > 0) {
      headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
  }

  // POST body parametreleri
  const bodyMatch = input.match(/\n\n(.+)$/s);
  if (bodyMatch) {
    try {
      const bodyParams = new URLSearchParams(bodyMatch[1]!);
      bodyParams.forEach((v, k) => { params[k] = v; });
    } catch { /* ignore */ }
  }

  return { url: url || input.split('\n')[0]!.trim(), params, headers };
}

// ─── Ana Analiz Fonksiyonu ───────────────────────────────────────────────────

export function analyzeWeb(input: string): WebAnalysisResult {
  const { url, params, headers } = parseUrlAndParams(input);
  const vulns: VulnDetail[] = [];
  const recommendations: string[] = [];
  const tools: string[] = [];
  const flags: string[] = [];

  // Flag arama — header'larda
  for (const [k, v] of Object.entries(headers)) {
    if (/flag|secret|ctf|x-flag/i.test(k) || /flag\{[^}]+\}/i.test(v)) {
      const match = v.match(/flag\{[^}]+\}/i);
      if (match) flags.push(match[0]);
      else flags.push(`${k}: ${v}`);
    }
  }

  // Flag arama — response body
  const bodyFlags = input.match(/flag\{[^}]+\}/gi) ?? [];
  flags.push(...bodyFlags);

  // Analizler
  vulns.push(...detectSQLi(input, params));
  vulns.push(...detectXSS(input, headers, params));
  vulns.push(...detectLFI(url, params));
  vulns.push(...detectIDOR(url, params));

  // Dizin keşfi
  if (url) {
    const baseUrl = url.split('?')[0]!.replace(/\/[^/]*\.[a-z]+$/, '');
    const discovery = directoryDiscovery(baseUrl);
    recommendations.push('Kritik path\'ler kontrol edilmeli:');
    recommendations.push(...discovery.paths.slice(0, 5));
    tools.push(...discovery.commands);
  }

  // Güvenlik header eksiklikleri
  const secHeaders = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy'];
  const missingHeaders = secHeaders.filter(h => !(h in headers));
  if (missingHeaders.length > 0) {
    recommendations.push(`Eksik güvenlik header'ları: ${missingHeaders.join(', ')}`);
  }

  // Hassas bilgi header'ları
  if (headers['server']) recommendations.push(`⚠️  Server header versiyon açıklıyor: ${headers['server']}`);
  if (headers['x-powered-by']) recommendations.push(`⚠️  X-Powered-By teknoloji açıklıyor: ${headers['x-powered-by']}`);

  // Tool önerileri
  const criticalVulns = vulns.filter(v => v.severity === 'critical' || v.severity === 'high');
  for (const v of criticalVulns) {
    if (v.tool_command) tools.push(v.tool_command);
  }

  if (vulns.some(v => v.type.includes('SQL'))) tools.push('sqlmap', 'ghauri');
  if (vulns.some(v => v.type.includes('XSS'))) tools.push('dalfox', 'xsser');
  if (vulns.some(v => v.type.includes('LFI'))) tools.push('ffuf', 'dotdotpwn');

  return {
    target: url || input.slice(0, 80),
    vulnerabilities_found: vulns,
    recommendations,
    tools_suggested: [...new Set(tools)],
    flags_found: [...new Set(flags)],
  };
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfWebAnalyzerTool: ToolDefinition = {
  name: 'ctf_web_analyzer',
  description:
    'CTF web güvenliği analizi: SQLi, XSS, LFI/Path Traversal, IDOR tespiti. ' +
    'URL, HTTP isteği veya response içeriği ver. ' +
    'Zafiyet tespiti, payload önerileri ve tool komutları üretir.',
  inputSchema: {
    type: 'object',
    properties: {
      input: { type: 'string', description: 'URL, HTTP isteği veya response içeriği' },
    },
    required: ['input'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(raw: Record<string, unknown>): Promise<ToolResult> {
    const input = String(raw['input'] ?? '').trim();
    if (!input) return { output: 'Hata: input boş olamaz.', isError: true };

    const result = analyzeWeb(input);
    const lines: string[] = [
      '┌─ WEB GÜVENLİK ANALİZİ ──────────────────────────────────────┐',
      `│ Hedef: ${result.target.slice(0, 55)}`,
      `│ Zafiyet: ${result.vulnerabilities_found.length} | Flag: ${result.flags_found.length}`,
      '└─────────────────────────────────────────────────────────────┘',
    ];

    if (result.flags_found.length > 0) {
      lines.push(`\n🎯 FLAG BULUNDU: ${result.flags_found.join(', ')}`);
    }

    if (result.vulnerabilities_found.length > 0) {
      lines.push('\n🔴 Zafiyetler:');
      for (const v of result.vulnerabilities_found) {
        lines.push(`  [${v.severity.toUpperCase()}] ${v.type}${v.parameter ? ` (param: ${v.parameter})` : ''}`);
        lines.push(`    Kanıt: ${v.evidence}`);
        if (v.tool_command) lines.push(`    Komut: ${v.tool_command}`);
      }
    }

    if (result.recommendations.length > 0) {
      lines.push('\n📋 Öneriler:');
      result.recommendations.slice(0, 8).forEach(r => lines.push(`  → ${r}`));
    }

    if (result.tools_suggested.length > 0) {
      lines.push(`\n🛠️  Önerilen Araçlar: ${[...new Set(result.tools_suggested)].slice(0, 6).join(', ')}`);
    }

    lines.push('\n' + JSON.stringify(result, null, 2));
    return { output: lines.join('\n') };
  },
};

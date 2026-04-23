/**
 * @fileoverview Permission Classifier — araç çağrılarını güvenlik açısından sınıflandırır.
 * Kural tabanlı (ML değil) sınıflandırıcı: safe / confirm / deny.
 * Sadece bypass/auto modunda devreye girer.
 */

export type ToolClassification = 'safe' | 'confirm' | 'deny';

/** Her zaman güvenli olan araçlar (onay gerekmez) */
const ALWAYS_SAFE_TOOLS = new Set([
  'file_read',
  'search',
  'grep',
  'list_directory',
  'glob',
  'batch_read',
  'web_ara',
  'web_search',
  'web_fetch',
  'gorev_oku',
  'arac_ara',
  'git_status',
  'git_log',
  'git_diff',
  'repo_ozet',
  'memory_read',
  'lsp_diagnostics',
  'gorev_listele',
]);

/** Güvenli kabul edilen shell komut prefixi'leri */
const SAFE_SHELL_PREFIXES = [
  'cat ', 'ls ', 'ls\n', 'ls', 'find ', 'grep ', 'echo ',
  'pwd', 'date', 'which ', 'whoami', 'uname', 'df ', 'du ',
  'wc ', 'head ', 'tail ', 'sort ', 'uniq ', 'cut ', 'awk ',
  'sed ', 'diff ', 'file ', 'stat ', 'type ', 'env', 'printenv',
  'git status', 'git log', 'git diff', 'git show', 'git branch',
  'npm list', 'npm ls', 'node --version', 'npm --version',
];

/** Onay gerektiren shell komut kalıpları */
const CONFIRM_SHELL_PATTERNS = [
  /\brm\b/, /\bmv\b/, /\bchmod\b/, /\bchown\b/,
  /\bcurl\b/, /\bwget\b/, /\bscp\b/, /\brsync\b/,
  /\bapt\b/, /\byum\b/, /\bdnf\b/, /\bpip\b/,
  /\bnpm install\b/, /\bnpm run\b/, /\byarn\b/,
  /\bsystemctl\b/, /\bservice\b/, /\bkill\b/, /\bpkill\b/,
  /\bmkdir\b/, /\btouch\b/, /\bcp\b(?!\s*--)/,
  /\bssh\b/, /\btelnet\b/, /\bnc\b/, /\bnetcat\b/,
];

/** Kesinlikle reddedilecek kalıplar */
const DENY_PATTERNS = [
  /rm\s+-rf?\s+\/(?!\w)/,          // rm -rf /
  /rm\s+-rf?\s+\*$/,               // rm -rf *
  /sudo\s+rm/,                     // sudo rm
  /:\s*\(\s*\)\s*\{.*\}/,         // fork bomb
  /dd\s+if=.*of=\/dev\//,          // disk overwrite
  /mkfs\./,                        // format disk
  />.*\/dev\/sd[a-z]/,             // write to disk device
];

/**
 * Araç çağrısını sınıflandır.
 * @returns 'safe' | 'confirm' | 'deny'
 */
export function classifyTool(
  toolName: string,
  input: Record<string, unknown>,
): ToolClassification {
  // Her zaman güvenli araçlar
  if (ALWAYS_SAFE_TOOLS.has(toolName)) return 'safe';

  // Shell komutu özel mantığı
  if (toolName === 'shell_execute' || toolName === 'bash') {
    const cmd = String(input.command ?? input.cmd ?? '').trim();

    // Deny kalıpları
    for (const pattern of DENY_PATTERNS) {
      if (pattern.test(cmd)) return 'deny';
    }

    // Onay gerektiren kalıplar
    for (const pattern of CONFIRM_SHELL_PATTERNS) {
      if (pattern.test(cmd)) return 'confirm';
    }

    // Güvenli prefix'ler
    for (const prefix of SAFE_SHELL_PREFIXES) {
      if (cmd.toLowerCase().startsWith(prefix.toLowerCase())) return 'safe';
    }

    // Bilinmeyen shell komutu → onay iste
    return 'confirm';
  }

  // Dosya yazma — uzantıya göre karar ver
  if (toolName === 'file_write' || toolName === 'file_edit') {
    const path = String(input.path ?? '');
    const safeExts = ['.md', '.txt', '.json', '.yaml', '.yml', '.env.example', '.gitignore'];
    const ext = path.slice(path.lastIndexOf('.')).toLowerCase();
    if (safeExts.some(e => path.endsWith(e))) return 'safe';
    // Kaynak kod dosyaları → onay iste
    return 'confirm';
  }

  // agent_spawn → her zaman onay
  if (toolName === 'agent_spawn') return 'confirm';

  // Diğer araçlar — varsayılan olarak onay iste
  return 'confirm';
}

/**
 * ToolExecutor entegrasyonu için: Bu araç auto-approve edilebilir mi?
 * Sadece 'full' izin seviyesinde veya araç 'safe' sınıfındaysa true döner.
 */
export function shouldAutoApprove(
  toolName: string,
  input: Record<string, unknown>,
  permissionLevel: string,
): boolean {
  if (permissionLevel === 'full') return true;
  return classifyTool(toolName, input) === 'safe';
}

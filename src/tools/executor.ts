/**
 * @fileoverview Tool executor — validates input, checks permissions, executes.
 */

import type {
  ToolDefinition,
  ToolResult,
  ToolPermissionConfig,
  ToolCallRecord,
  PermissionLevel,
  SecurityProfile,
} from '../types.js';
import type { ToolRegistry } from './registry.js';
import { isToolAllowed } from './permission.js';
import { EXTERNAL_TIMEOUT_OUTPUT_FRAGMENT } from './external-tool.js';
import * as readline from 'readline';
import { readFile } from 'fs/promises';
import { resolve as resolvePath, join as joinPath } from 'path';
import chalk from 'chalk';
import { cmd } from '../theme.js';
import { logToolMetric } from '../storage/tool-metrics.js';
import { truncateToolOutput } from '../truncate.js';
import { maskSensitiveOutput } from '../tool-output-masking.js';

const MAX_TOOL_OUTPUT_CHARS = 20_000;

// Araçlar çalışmadan önce cwd'deki .env dosyası bunlara enjekte edilir.
const ENV_INJECT_TOOLS = new Set([
  'shell', 'sqlmap', 'nmap', 'nikto', 'gobuster', 'whois', 'dig', 'whatweb',
  'ffuf', 'nuclei', 'masscan', 'nc', 'wpscan', 'subfinder', 'john', 'hashcat',
]);

// Tools that are always safe (read-only) and never need confirmation in 'normal' mode.
const READ_ONLY_TOOLS = new Set([
  'file_read',
  'search',
  'grep',
  'list_directory',
  'glob',
  'batch_read',
  'gorev_oku',
  'gorev_yaz',
  'arac_ara',
  'web_ara',
]);

export class ToolExecutor {
  private permissionLevel: PermissionLevel = 'normal';
  private whitelistedTools: Set<string> = new Set();
  
  public onConfirmStart?: () => void;
  public onConfirmEnd?: () => void;

  constructor(
    private readonly registry: ToolRegistry,
    private permissionConfig: ToolPermissionConfig,
    private readonly confirmFn?: (message: string) => Promise<boolean>,
  ) {}

  /** Change the runtime permission level. */
  setPermissionLevel(level: PermissionLevel): void {
    this.permissionLevel = level;
    // Reset whitelist when level changes
    this.whitelistedTools.clear();
  }

  getPermissionLevel(): PermissionLevel { return this.permissionLevel; }
  getSecurityProfile(): SecurityProfile { return this.permissionConfig.securityProfile ?? 'standard'; }
  setSecurityProfile(profile: SecurityProfile): void {
    this.permissionConfig = { ...this.permissionConfig, securityProfile: profile };
  }

  /** Whitelist a tool so it will never prompt again in this session. */
  whitelistTool(name: string): void { this.whitelistedTools.add(name); }

  async execute(
    toolName: string,
    input: Record<string, unknown>,
    cwd: string,
  ): Promise<{ result: ToolResult; record: ToolCallRecord }> {
    const startTime = Date.now();
    const finalize = async (result: ToolResult): Promise<{ result: ToolResult; record: ToolCallRecord }> => {
      const durationMs = Date.now() - startTime;
      const isError = result.isError ?? false;
      const isTimeout = result.output.includes(EXTERNAL_TIMEOUT_OUTPUT_FRAGMENT);
      await logToolMetric({
        timestamp: new Date().toISOString(),
        toolName,
        durationMs,
        isError,
        isTimeout,
      });
      return {
        result,
        record: { toolName, input, output: result.output, durationMs, isError, newCwd: result.newCwd },
      };
    };
    const tool = this.registry.get(toolName);

    if (!tool) {
      const result: ToolResult = { output: `Hata: Bilinmeyen araç "${toolName}".`, isError: true };
      return finalize(result);
    }

    // Permission check (static config)
    const permission = isToolAllowed(tool, input, this.permissionConfig);
    if (!permission.allowed) {
      const result: ToolResult = { output: `Erişim engellendi: ${permission.reason}`, isError: true };
      return finalize(result);
    }

    // ─── Runtime confirmation based on PermissionLevel ─────────────
    const needsConfirm = this.shouldConfirm(tool, input, permission.needsConfirmation);

    if (needsConfirm) {
      // Diff önizleme: onay öncesi değişiklikleri göster
      if (toolName === 'file_write' || toolName === 'file_edit') {
        await this.showDiffPreview(toolName, input, cwd);
      }
      const answer = await this.requestConfirmation(tool, input);
      if (answer === 'no') {
        const result: ToolResult = { output: 'Kullanıcı bu aracın çalıştırılmasına izin vermedi.', isError: true };
        return finalize(result);
      }
      if (answer === 'always') {
        this.whitelistedTools.add(toolName);
      }
    }

    // .env bağlamı: FETIH_LOAD_ENV=false ile devre dışı bırakılabilir
    let envSnapshot: Record<string, string | undefined> = {};
    if (process.env['FETIH_LOAD_ENV'] !== 'false' && ENV_INJECT_TOOLS.has(toolName)) {
      envSnapshot = await this.loadDotEnv(cwd);
    }

    // Execute
    try {
      try {
        const result = await tool.execute(input, cwd);
        // #14 Araç sonucu boyut sınırı
        let output = result.output;
        let isTruncated = false;
        if (output.length > MAX_TOOL_OUTPUT_CHARS) {
          output = truncateToolOutput(output, MAX_TOOL_OUTPUT_CHARS);
          isTruncated = true;
        }
        // #3 Hassas bilgileri maskele
        const { masked, count } = maskSensitiveOutput(output);
        if (count > 0) output = masked;

        // v3.9.5: Audit log
        try {
          const { recordToolExecution } = await import('../security/index.js');
          recordToolExecution(toolName, input, true);
        } catch { /* audit sessizce başarısız olabilir */ }

        return finalize({ ...result, output, isTruncated });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);

        // v3.9.5: Audit log (hata)
        try {
          const { recordToolExecution } = await import('../security/index.js');
          recordToolExecution(toolName, input, false);
        } catch { /* audit sessizce başarısız olabilir */ }

        const result: ToolResult = { output: `Araç çalışma hatası: ${message}`, isError: true };
        return finalize(result);
      }
    } finally {
      this.restoreEnv(envSnapshot);
    }
  }

  /** Decide if this tool call needs confirmation based on permission level. */
  private shouldConfirm(tool: ToolDefinition, input: Record<string, unknown>, staticNeedsConfirm: boolean): boolean {
    // Auto-approve mode (--auto / -y flag)
    if (this.confirmFn) return false;

    // Session whitelist (user said "bir daha sorma")
    if (this.whitelistedTools.has(tool.name)) return false;

    switch (this.permissionLevel) {
      case 'full':
        // Never ask
        return false;

      case 'normal':
        // Read-only tools: no confirm
        if (READ_ONLY_TOOLS.has(tool.name)) return false;
        // Shell with safe commands: no confirm (handled by staticNeedsConfirm from permission.ts)
        return staticNeedsConfirm;

      case 'dar':
        // Always ask for everything
        return true;

      default:
        return staticNeedsConfirm;
    }
  }

  /**
   * Ask the user for confirmation. Uses a simple readline prompt (NOT @clack/prompts)
   * to avoid the double-render bug caused by clack creating its own readline interface.
   *
   * Returns: 'yes' | 'no' | 'always'
   */
  private async requestConfirmation(tool: ToolDefinition, input: Record<string, unknown>): Promise<'yes' | 'no' | 'always'> {
    if (this.onConfirmStart) this.onConfirmStart();
    const summary = this.formatToolSummary(tool, input);

    return new Promise((resolve) => {
      const prompt = `${chalk.yellow('  ⚠')} ${summary} ${chalk.dim('[E]vet / [H]ayır / [D]aima')} `;
      process.stdout.write(prompt);

      const wasRaw = process.stdin.isRaw;

      if (process.stdin.isTTY) process.stdin.setRawMode(true);
      process.stdin.resume();

      const cleanup = () => {
        process.stdin.removeListener('data', onData);
        process.removeListener('SIGINT', onSigInt);
        // Raw mode'u geri al — readline tekrar devralacak
        if (process.stdin.isTTY) process.stdin.setRawMode(wasRaw);
      };

      const finishAndResolve = (val: 'yes' | 'no' | 'always') => {
        cleanup();
        if (this.onConfirmEnd) this.onConfirmEnd();
        resolve(val);
      };

      const onData = (buf: Buffer) => {
        const key = buf.toString().toLowerCase().trim();
        // Tuş karakterini terminale YAZMA — sadece cevabı yaz
        if (key === 'e' || key === 'y' || key === '\r' || key === '\n') {
          process.stdout.write(chalk.green('Evet') + '\n');
          finishAndResolve('yes');
        } else if (key === 'd' || key === 'a') {
          process.stdout.write(cmd('Daima') + '\n');
          finishAndResolve('always');
        } else if (key === 'h' || key === 'n') {
          process.stdout.write(chalk.red('Hayır') + '\n');
          finishAndResolve('no');
        } else if (key === '\x03') {
          // Ctrl+C
          process.stdout.write(chalk.red('İptal') + '\n');
          finishAndResolve('no');
        }
        // Diğer tuşları yut — sohbete gitmesin
      };

      process.stdin.on('data', onData);

      const onSigInt = () => {
        process.stdout.write(chalk.red('İptal edildi') + '\n');
        finishAndResolve('no');
      };
      
      process.on('SIGINT', onSigInt);
    });
  }

  private formatToolSummary(tool: ToolDefinition, input: Record<string, unknown>): string {
    if (tool.name === 'shell') return `Komut: ${chalk.bold(String(input.command ?? '').slice(0, 80))}`;
    if (tool.name === 'file_write') return `Yaz: ${chalk.bold(String(input.path ?? ''))}`;
    if (tool.name === 'file_edit') return `Düzenle: ${chalk.bold(String(input.path ?? ''))}`;
    if (tool.name === 'mcp_arac') {
      return `MCP ${chalk.bold(String(input.sunucu ?? ''))} → ${chalk.bold(String(input.islem ?? ''))}`;
    }
    return `${tool.name}(${JSON.stringify(input).slice(0, 80)})`;
  }

  /** Onay öncesi basit satır karşılaştırmalı diff önizleme gösterir. */
  private async showDiffPreview(toolName: string, input: Record<string, unknown>, cwd: string): Promise<void> {
    const SEP = chalk.dim('  ' + '─'.repeat(50));
    process.stdout.write('\n' + SEP + '\n');
    process.stdout.write(chalk.dim('  Diff Önizleme\n') + SEP + '\n');

    if (toolName === 'file_write') {
      const filePath = resolvePath(cwd, String(input['path'] ?? ''));
      const newContent = String(input['content'] ?? '');
      let oldContent = '';
      try { oldContent = await readFile(filePath, 'utf-8'); } catch { /* yeni dosya */ }

      if (oldContent) {
        const oldLines = oldContent.split('\n');
        const limit = 12;
        for (const l of oldLines.slice(0, limit)) process.stdout.write(chalk.red(`  - ${l}\n`));
        if (oldLines.length > limit) process.stdout.write(chalk.dim(`  ... ${oldLines.length - limit} satır daha\n`));
      }
      const newLines = newContent.split('\n');
      const limit = 12;
      for (const l of newLines.slice(0, limit)) process.stdout.write(chalk.green(`  + ${l}\n`));
      if (newLines.length > limit) process.stdout.write(chalk.dim(`  ... ${newLines.length - limit} satır daha\n`));
    } else if (toolName === 'file_edit') {
      const oldStr = String(input['old_string'] ?? '');
      const newStr = String(input['new_string'] ?? '');
      const limit = 8;
      const oldLines = oldStr.split('\n');
      const newLines = newStr.split('\n');
      for (const l of oldLines.slice(0, limit)) process.stdout.write(chalk.red(`  - ${l}\n`));
      if (oldLines.length > limit) process.stdout.write(chalk.dim(`  ... ${oldLines.length - limit} satır daha\n`));
      for (const l of newLines.slice(0, limit)) process.stdout.write(chalk.green(`  + ${l}\n`));
      if (newLines.length > limit) process.stdout.write(chalk.dim(`  ... ${newLines.length - limit} satır daha\n`));
    }

    process.stdout.write(SEP + '\n');
  }

  /** cwd içindeki .env dosyasını yükler, process.env'e enjekte eder ve snapshot döndürür. */
  private async loadDotEnv(cwd: string): Promise<Record<string, string | undefined>> {
    const snapshot: Record<string, string | undefined> = {};
    try {
      const raw = await readFile(joinPath(cwd, '.env'), 'utf-8');
      for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx === -1) continue;
        const key = trimmed.slice(0, eqIdx).trim();
        const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
        if (!key) continue;
        snapshot[key] = process.env[key];
        process.env[key] = val;
      }
    } catch { /* .env yok veya okunamadı */ }
    return snapshot;
  }

  /** loadDotEnv tarafından alınan snapshot'ı geri yükler. */
  private restoreEnv(snapshot: Record<string, string | undefined>): void {
    for (const [key, val] of Object.entries(snapshot)) {
      if (val === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = val;
      }
    }
  }
}

/**
 * @fileoverview Shell tool — PTY destekli cross-platform komut çalıştırma.
 * node-pty ile gerçek pseudo-terminal: sudo, ssh gibi interaktif komutlar çalışır.
 * node-pty yoksa eski spawn yöntemine düşer.
 * v3.9.6: Shell güvenlik analizi entegrasyonu.
 */

import { spawn } from 'child_process';
import { platform, tmpdir } from 'os';
import { join } from 'path';
import { readFileSync, unlinkSync } from 'fs';
import { randomUUID } from 'crypto';
import type { ToolDefinition, ToolResult } from '../types.js';
import { enterPtyMode, exitPtyMode } from '../pty-mode.js';
import { analyzeShellCommand, formatSecurityReport } from './shell-security.js';

const DEFAULT_TIMEOUT = 30_000;

let ptyLib: typeof import('node-pty') | null = null;
(async () => {
  try {
    ptyLib = await import('node-pty');
  } catch { /* node-pty yok → spawn fallback */ }
})();

export const shellTool: ToolDefinition = {
  name: 'shell',
  description:
    'Kabuk komutu calistirir. Linux/macOS bash, Windows PowerShell kullanir. ' +
    'Dosya islemleri, betik, paket kurulumu, git, sudo vb. icin kullan. ' +
    'PTY destekli: sudo sifre isterleri kullaniciya gorunur ve girilebilir.',
  inputSchema: {
    type: 'object',
    properties: {
      command: { type: 'string', description: 'Çalıştırılacak komut.' },
      timeout: { type: 'number', description: `Zaman aşımı (ms). Varsayılan: ${DEFAULT_TIMEOUT}` },
    },
    required: ['command'],
  },
  isDestructive: false,
  requiresConfirmation: true,

  async execute(input: Record<string, unknown>, cwd: string): Promise<ToolResult> {
    const rawCommand = input.command as string;
    const timeoutMs = (input.timeout as number) ?? DEFAULT_TIMEOUT;

    // v3.9.6: Shell güvenlik analizi
    const securityAnalysis = analyzeShellCommand(rawCommand);
    let securityWarning = '';
    if (securityAnalysis.findings.length > 0) {
      securityWarning = formatSecurityReport(securityAnalysis);
      if (securityAnalysis.severity === 'block') {
        try {
          const { recordSecurityViolation } = await import('../security/index.js');
          recordSecurityViolation('Shell güvenlik ihlali', {
            command: rawCommand.slice(0, 200),
            findings: securityAnalysis.findings.map(f => `${f.type}: ${f.message}`),
          });
        } catch {}
      }
    }

    const isWindows = platform() === 'win32';
    const shell = isWindows ? 'powershell.exe' : 'bash';

    const cwdFile = join(tmpdir(), `seth-cwd-${randomUUID()}`);
    let command: string;

    if (isWindows) {
      command = `${rawCommand}; Get-Location | Select-Object -ExpandProperty Path | Out-File -FilePath "${cwdFile}" -Encoding utf8`;
    } else {
      command = `${rawCommand} && pwd -P > "${cwdFile}" || { pwd -P > "${cwdFile}"; exit 1; }`;
    }

    if (ptyLib && !isWindows) {
      return runWithPty(ptyLib, shell, command, cwd, cwdFile, timeoutMs, securityWarning);
    }
    return runWithSpawn(shell, command, cwd, cwdFile, timeoutMs, isWindows, securityWarning);
  },
};

// ─── PTY yolu ────────────────────────────────────────────────────────────────

async function runWithPty(
  pty: typeof import('node-pty'),
  shell: string,
  command: string,
  cwd: string,
  cwdFile: string,
  timeoutMs: number,
  securityWarning: string,
): Promise<ToolResult> {
  return new Promise<ToolResult>((resolve) => {
    const cols = process.stdout.columns || 80;
    const rows = process.stdout.rows || 24;

    const ptyProc = pty.spawn(shell, ['-c', command], {
      name: 'xterm-256color',
      cols,
      rows,
      cwd,
      env: { ...process.env } as Record<string, string>,
    });

    const outputChunks: string[] = [];
    let settled = false;
    let timedOut = false;

    ptyProc.onData((data) => {
      process.stdout.write(data);
      outputChunks.push(data);
    });

    enterPtyMode((data) => ptyProc.write(data));

    const timer = setTimeout(() => {
      timedOut = true;
      try { ptyProc.kill(); } catch {}
    }, timeoutMs);

    ptyProc.onExit(({ exitCode }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      exitPtyMode();
      process.stdout.write('\n');

      const rawOutput = outputChunks.join('');
      const cleanOutput = stripAnsiCodes(rawOutput);

      const code = exitCode ?? (timedOut ? 124 : 1);
      let output = cleanOutput.trim() || (code === 0 ? '(çıktı yok)' : `(exit code: ${code})`);
      if (code !== 0 && cleanOutput.trim()) output += `\n(exit code: ${code})`;
      if (timedOut) output += '\n(zaman aşımı)';

      let newCwd: string | undefined;
      try {
        newCwd = readFileSync(cwdFile, 'utf8').trim();
        unlinkSync(cwdFile);
      } catch {}

      const secOutput = securityWarning ? '\n' + securityWarning + '\n' : '';
      resolve({
        output: truncateOutput(output) + secOutput,
        isError: code !== 0,
        newCwd: newCwd && newCwd !== cwd ? newCwd : undefined,
      });
    });
  });
}

// ─── Spawn fallback ──────────────────────────────────────────────────────────

function runWithSpawn(
  shell: string,
  command: string,
  cwd: string,
  cwdFile: string,
  timeoutMs: number,
  isWindows: boolean,
  securityWarning: string,
): Promise<ToolResult> {
  const shellArgs = isWindows
    ? ['-NoProfile', '-NonInteractive', '-Command', command]
    : ['-c', command];

  return new Promise<ToolResult>((resolve) => {
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    const child = spawn(shell, shellArgs, {
      cwd,
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    child.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

    let settled = false;
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    const finish = (exitCode: number) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      const stdout = Buffer.concat(stdoutChunks).toString('utf8');
      const stderr = Buffer.concat(stderrChunks).toString('utf8');

      let output = '';
      if (stdout) output += stdout;
      if (stderr) output += (output ? '\n--- stderr ---\n' : '') + stderr;
      if (!output) output = exitCode === 0 ? '(completed with no output)' : `(exit code: ${exitCode})`;
      if (exitCode !== 0 && output) output += `\n(exit code: ${exitCode})`;
      if (timedOut) output += '\n(timed out)';

      let newCwd: string | undefined;
      try {
        newCwd = readFileSync(cwdFile, 'utf8').trim();
        unlinkSync(cwdFile);
      } catch {}

      const secOutput = securityWarning ? '\n' + securityWarning + '\n' : '';
      resolve({
        output: truncateOutput(output) + secOutput,
        isError: exitCode !== 0,
        newCwd: newCwd && newCwd !== cwd ? newCwd : undefined,
      });
    };

    child.on('close', (code) => finish(code ?? (timedOut ? 124 : 1)));
    child.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        try { unlinkSync(cwdFile); } catch {}
        const secOutput = securityWarning ? '\n' + securityWarning + '\n' : '';
        resolve({ output: `Error: ${err.message}` + secOutput, isError: true });
      }
    });
  });
}

// ─── Yardımcılar ─────────────────────────────────────────────────────────────

function truncateOutput(output: string, maxLen = 10000): string {
  if (output.length <= maxLen) return output;
  const half = Math.floor(maxLen / 2);
  return `${output.slice(0, half)}\n\n... [${output.length - maxLen} chars truncated] ...\n\n${output.slice(-half)}`;
}

function stripAnsiCodes(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
            .replace(/\x1b\][^\x07]*\x07/g, '')
            .replace(/\x1b[()][AB012]/g, '')
            .replace(/\r/g, '');
}

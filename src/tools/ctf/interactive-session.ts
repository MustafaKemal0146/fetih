/**
 * @fileoverview Fetih CTF Interactive Session — child_process spawn ile gdb/msfconsole/nc tarzı
 * uzun süreli komutları yönet. PTY yok (vim/less çalışmaz), ama text-mode tool'lar için yeterli.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { registerCleanup } from '../../lifecycle.js';

interface Session {
  proc: ChildProcessWithoutNullStreams;
  buffer: Buffer;
  closed: boolean;
  exitCode: number | null;
  command: string;
  startedAt: number;
}

const sessions = new Map<string, Session>();
let cleanupRegistered = false;
let nextId = 1;

function ensureCleanup(): void {
  if (cleanupRegistered) return;
  cleanupRegistered = true;
  registerCleanup(async () => {
    for (const s of sessions.values()) {
      try { s.proc.kill('SIGKILL'); } catch { /* ignore */ }
    }
    sessions.clear();
  });
}

async function startSession(command: string, args: string[], cwd?: string): Promise<{ id: string; session: Session }> {
  ensureCleanup();
  const id = `s${nextId++}`;
  const proc = spawn(command, args, {
    cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, TERM: 'dumb' }, // dumb terminal — interaktif renk yok
  });
  const session: Session = {
    proc,
    buffer: Buffer.alloc(0),
    closed: false,
    exitCode: null,
    command: `${command} ${args.join(' ')}`,
    startedAt: Date.now(),
  };
  proc.stdout.on('data', chunk => { session.buffer = Buffer.concat([session.buffer, chunk]); });
  proc.stderr.on('data', chunk => { session.buffer = Buffer.concat([session.buffer, chunk]); });
  proc.on('close', code => { session.closed = true; session.exitCode = code; });
  proc.on('error', () => { session.closed = true; });

  // Process'in başlamasını ya da hemen exit etmesini bekle (kısa)
  await new Promise(r => setTimeout(r, 100));
  sessions.set(id, session);
  return { id, session };
}

async function recvUntil(session: Session, pattern: string, timeout: number): Promise<{ text: string; matched: boolean }> {
  const target = Buffer.from(pattern, 'utf8');
  const start = Date.now();
  while (true) {
    const idx = session.buffer.indexOf(target);
    if (idx >= 0) {
      const result = session.buffer.slice(0, idx + target.length);
      session.buffer = session.buffer.slice(idx + target.length);
      return { text: result.toString('utf8'), matched: true };
    }
    if (session.closed && session.buffer.length === 0) {
      return { text: '', matched: false };
    }
    if (Date.now() - start > timeout) {
      // Timeout — buffer'ın ne kadarı varsa dön (matched=false)
      const result = session.buffer; session.buffer = Buffer.alloc(0);
      return { text: result.toString('utf8'), matched: false };
    }
    await new Promise(r => setTimeout(r, 50));
  }
}

async function recvAll(session: Session, idleMs: number): Promise<string> {
  // Belli süre yeni byte gelmezse buffer'ı dön
  let lastSize = -1;
  let stableSince = Date.now();
  while (Date.now() - stableSince < idleMs) {
    if (session.buffer.length !== lastSize) {
      lastSize = session.buffer.length;
      stableSince = Date.now();
    }
    if (session.closed) break;
    await new Promise(r => setTimeout(r, 50));
  }
  const result = session.buffer; session.buffer = Buffer.alloc(0);
  return result.toString('utf8');
}

function send(session: Session, text: string): void {
  if (session.closed) throw new Error('Session kapalı');
  session.proc.stdin.write(text);
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const interactiveSessionTool: ToolDefinition = {
  name: 'interactive_session',
  description:
    'Uzun süreli interaktif process yönetimi (gdb, msfconsole, nc, telnet vb.). ' +
    'Eylemler: start (process spawn, ID döner), send/sendline (stdin\'e yaz), ' +
    'recv_until (pattern bekle), recvall (idle bekle), kill (sonlandır), list (aktif). ' +
    'PTY yok — vim/less çalışmaz; text-mode tool\'lar için ideal.',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['start', 'send', 'sendline', 'recv_until', 'recvall', 'kill', 'list'] },
      command: { type: 'string', description: 'start için komut (örn. "gdb")' },
      args: { type: 'array', items: { type: 'string' }, description: 'start için komut argümanları' },
      cwd: { type: 'string', description: 'start için working directory' },
      session: { type: 'string', description: 'Session ID (start sonrası dönen)' },
      data: { type: 'string', description: 'send/sendline için stdin verisi' },
      pattern: { type: 'string', description: 'recv_until için bekleme pattern' },
      timeout: { type: 'number', description: 'recv_until için ms (varsayılan 10000)' },
      idleMs: { type: 'number', description: 'recvall için idle threshold ms (varsayılan 1500)' },
    },
    required: ['action'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const action = String(input['action'] ?? '');
    const sid = input['session'] ? String(input['session']) : '';

    try {
      switch (action) {
        case 'start': {
          const command = String(input['command'] ?? '');
          if (!command) return { output: 'command gerekli', isError: true };
          const args = Array.isArray(input['args']) ? (input['args'] as string[]) : [];
          const cwd = input['cwd'] ? String(input['cwd']) : undefined;
          const { id, session } = await startSession(command, args, cwd);
          // Açılış çıktısını biraz topla
          await new Promise(r => setTimeout(r, 300));
          const initial = session.buffer.toString('utf8');
          session.buffer = Buffer.alloc(0);
          return {
            output: [
              `✓ Session başladı: ${id}`,
              `   Komut: ${session.command}`,
              `   PID: ${session.proc.pid}`,
              initial ? `   İlk çıktı (${initial.length} byte):\n${initial.slice(0, 500)}` : '',
            ].filter(Boolean).join('\n'),
            isError: false,
          };
        }

        case 'send':
        case 'sendline': {
          if (!sid) return { output: 'session ID gerekli', isError: true };
          const session = sessions.get(sid);
          if (!session) return { output: `Session yok: ${sid}`, isError: true };
          const data = String(input['data'] ?? '') + (action === 'sendline' ? '\n' : '');
          send(session, data);
          return { output: `✓ Gönderildi (${data.length} byte) → ${sid}`, isError: false };
        }

        case 'recv_until': {
          if (!sid) return { output: 'session ID gerekli', isError: true };
          const session = sessions.get(sid);
          if (!session) return { output: `Session yok: ${sid}`, isError: true };
          const pattern = String(input['pattern'] ?? '');
          if (!pattern) return { output: 'pattern gerekli', isError: true };
          const timeout = Number(input['timeout'] ?? 10_000);
          const r = await recvUntil(session, pattern, timeout);
          return {
            output: r.matched ? r.text : `[timeout — pattern "${pattern}" yok, alınan:]\n${r.text}`,
            isError: !r.matched,
          };
        }

        case 'recvall': {
          if (!sid) return { output: 'session ID gerekli', isError: true };
          const session = sessions.get(sid);
          if (!session) return { output: `Session yok: ${sid}`, isError: true };
          const idle = Number(input['idleMs'] ?? 1500);
          const text = await recvAll(session, idle);
          return { output: text, isError: false };
        }

        case 'kill': {
          if (!sid) return { output: 'session ID gerekli', isError: true };
          const session = sessions.get(sid);
          if (!session) return { output: `Session yok: ${sid}`, isError: false };
          try { session.proc.kill('SIGKILL'); } catch { /* ignore */ }
          sessions.delete(sid);
          return { output: `✓ Session kapatıldı: ${sid}`, isError: false };
        }

        case 'list': {
          if (sessions.size === 0) return { output: 'Aktif session yok', isError: false };
          const lines = ['Aktif sessions:'];
          for (const [id, s] of sessions.entries()) {
            const dur = ((Date.now() - s.startedAt) / 1000).toFixed(0);
            const status = s.closed ? `closed (exit=${s.exitCode})` : 'running';
            lines.push(`  ${id} | ${status} | ${dur}s | ${s.command.slice(0, 60)}`);
          }
          return { output: lines.join('\n'), isError: false };
        }

        default:
          return { output: `Bilinmeyen eylem: ${action}`, isError: true };
      }
    } catch (err) {
      return { output: `Hata: ${err instanceof Error ? err.message : String(err)}`, isError: true };
    }
  },
};

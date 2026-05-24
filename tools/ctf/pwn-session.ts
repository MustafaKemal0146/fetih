/**
 * @fileoverview Fetih CTF PWN Session — pwntools remote() benzeri TCP wrapper.
 * Net socket üzerinden host:port'a bağlan, send/recv/recv_until ile etkileş.
 * Kalıcı oturum: aynı tool ID üzerinden ardışık komut gönder.
 */

import { Socket } from 'net';
import type { ToolDefinition, ToolResult } from '../../types.js';
import { registerCleanup } from '../../lifecycle.js';

interface PwnSession {
  socket: Socket;
  buffer: Buffer;
  closed: boolean;
  host: string;
  port: number;
}

const sessions = new Map<string, PwnSession>();
let cleanupRegistered = false;

function ensureCleanup(): void {
  if (cleanupRegistered) return;
  cleanupRegistered = true;
  registerCleanup(async () => {
    for (const session of sessions.values()) {
      try { session.socket.destroy(); } catch { /* ignore */ }
    }
    sessions.clear();
  });
}

function makeId(host: string, port: number): string {
  return `${host}:${port}`;
}

async function connect(host: string, port: number, timeout = 10_000): Promise<PwnSession> {
  ensureCleanup();
  return new Promise((resolve, reject) => {
    const socket = new Socket();
    const session: PwnSession = { socket, buffer: Buffer.alloc(0), closed: false, host, port };
    socket.setTimeout(timeout);
    socket.on('data', (chunk: Buffer) => { session.buffer = Buffer.concat([session.buffer, chunk]); });
    socket.on('close', () => { session.closed = true; });
    socket.on('error', () => { session.closed = true; });
    socket.connect(port, host, () => {
      socket.setTimeout(0);
      resolve(session);
    });
    socket.once('error', err => reject(err));
  });
}

async function recvUntil(session: PwnSession, pattern: string | Buffer, timeout = 10_000): Promise<Buffer> {
  const target = typeof pattern === 'string' ? Buffer.from(pattern, 'utf8') : pattern;
  const start = Date.now();
  while (true) {
    const idx = session.buffer.indexOf(target);
    if (idx >= 0) {
      const result = session.buffer.slice(0, idx + target.length);
      session.buffer = session.buffer.slice(idx + target.length);
      return result;
    }
    if (session.closed) {
      const result = session.buffer; session.buffer = Buffer.alloc(0); return result;
    }
    if (Date.now() - start > timeout) throw new Error(`recv_until timeout (${timeout}ms) — pattern bulunamadı`);
    await new Promise(r => setTimeout(r, 50));
  }
}

async function recvN(session: PwnSession, n: number, timeout = 5_000): Promise<Buffer> {
  const start = Date.now();
  while (session.buffer.length < n && !session.closed) {
    if (Date.now() - start > timeout) break;
    await new Promise(r => setTimeout(r, 50));
  }
  const take = Math.min(n, session.buffer.length);
  const result = session.buffer.slice(0, take);
  session.buffer = session.buffer.slice(take);
  return result;
}

async function recvAll(session: PwnSession, timeout = 2_000): Promise<Buffer> {
  // Bir süre yeni veri gelmezse buffer'ı dön
  await new Promise(r => setTimeout(r, timeout));
  const result = session.buffer; session.buffer = Buffer.alloc(0); return result;
}

function send(session: PwnSession, data: string | Buffer): void {
  if (session.closed) throw new Error('Bağlantı kapalı');
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  session.socket.write(buf);
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const pwnSessionTool: ToolDefinition = {
  name: 'pwn_session',
  description:
    'PWN remote socket wrapper (pwntools remote() benzeri). Eylemler: ' +
    'connect (TCP bağlan), send (raw veri), sendline (\\n eklenmiş), recv_until (pattern bekle), ' +
    'recv (N byte), recvall (timeout sonrası tüm buffer), close. ' +
    'Aynı host:port aynı oturum — ardışık komutlar etkileşimli akış oluşturur. ' +
    'Sınav remote PWN için: "nc challenge.tld 1337" yerine bunu kullan.',
  inputSchema: {
    type: 'object',
    properties: {
      action: {
        type: 'string',
        enum: ['connect', 'send', 'sendline', 'recv_until', 'recv', 'recvall', 'close'],
      },
      host: { type: 'string', description: 'connect için hedef host' },
      port: { type: 'number', description: 'connect için hedef port' },
      data: { type: 'string', description: 'send/sendline için veri (raw bytes string)' },
      pattern: { type: 'string', description: 'recv_until için bekleme pattern' },
      n: { type: 'number', description: 'recv için byte sayısı' },
      timeout: { type: 'number', description: 'milisaniye (varsayılan 10000)' },
      session: { type: 'string', description: 'Oturum ID (host:port). Yoksa son aktif oturum kullanılır' },
    },
    required: ['action'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const action = String(input['action'] ?? '');
    const sessionId = input['session'] ? String(input['session']) :
      (input['host'] && input['port'] ? makeId(String(input['host']), Number(input['port'])) :
      [...sessions.keys()].pop() ?? '');

    try {
      switch (action) {
        case 'connect': {
          const host = String(input['host'] ?? '');
          const port = Number(input['port'] ?? 0);
          if (!host || !port) return { output: 'host ve port gerekli', isError: true };
          const id = makeId(host, port);
          if (sessions.has(id)) {
            try { sessions.get(id)!.socket.destroy(); } catch { /* ignore */ }
            sessions.delete(id);
          }
          const timeout = Number(input['timeout'] ?? 10_000);
          const session = await connect(host, port, timeout);
          sessions.set(id, session);
          return { output: `✓ Bağlandı: ${id} (oturum ID: ${id})`, isError: false };
        }
        case 'send':
        case 'sendline': {
          const session = sessions.get(sessionId);
          if (!session) return { output: `Oturum bulunamadı: ${sessionId}. Önce connect.`, isError: true };
          const data = String(input['data'] ?? '') + (action === 'sendline' ? '\n' : '');
          send(session, data);
          return { output: `✓ Gönderildi (${data.length} byte) → ${sessionId}`, isError: false };
        }
        case 'recv_until': {
          const session = sessions.get(sessionId);
          if (!session) return { output: `Oturum bulunamadı: ${sessionId}`, isError: true };
          const pattern = String(input['pattern'] ?? '');
          const timeout = Number(input['timeout'] ?? 10_000);
          const result = await recvUntil(session, pattern, timeout);
          return { output: result.toString('utf8'), isError: false };
        }
        case 'recv': {
          const session = sessions.get(sessionId);
          if (!session) return { output: `Oturum bulunamadı: ${sessionId}`, isError: true };
          const n = Number(input['n'] ?? 1024);
          const timeout = Number(input['timeout'] ?? 5_000);
          const result = await recvN(session, n, timeout);
          return { output: result.toString('utf8'), isError: false };
        }
        case 'recvall': {
          const session = sessions.get(sessionId);
          if (!session) return { output: `Oturum bulunamadı: ${sessionId}`, isError: true };
          const timeout = Number(input['timeout'] ?? 2_000);
          const result = await recvAll(session, timeout);
          return { output: result.toString('utf8'), isError: false };
        }
        case 'close': {
          const session = sessions.get(sessionId);
          if (!session) return { output: `Oturum yok: ${sessionId}`, isError: false };
          try { session.socket.destroy(); } catch { /* ignore */ }
          sessions.delete(sessionId);
          return { output: `✓ Kapatıldı: ${sessionId}`, isError: false };
        }
        default:
          return { output: `Bilinmeyen eylem: ${action}`, isError: true };
      }
    } catch (err) {
      return { output: `Hata: ${err instanceof Error ? err.message : String(err)}`, isError: true };
    }
  },
};

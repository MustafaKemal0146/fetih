import express, { type Request, type Response } from 'express';
import { createServer } from 'http';
import { WebSocketServer, type WebSocket as WS, type RawData } from 'ws';
import open from 'open';
import chalk from 'chalk';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { existsSync } from 'fs';
import { spawnSync, spawn as spawnAsync } from 'child_process';
import { webUIController } from './controller.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getPublicPath(): string {
  // Önce dist/web-ui (Vite build), sonra dist/web (TS build), sonra web/public
  const distWebUI = resolve(__dirname, '..', '..', 'dist', 'web-ui');
  if (existsSync(distWebUI)) return distWebUI;
  const distWeb = resolve(__dirname, '..', '..', 'dist', 'web');
  if (existsSync(distWeb)) return distWeb;
  return resolve(__dirname, '..', '..', 'web', 'public');
}

export async function startWebServer(port = 4321) {
  const app = express();
  const server = createServer(app);
  const wss = new WebSocketServer({ server });

  webUIController.setServer(wss);

  app.use(express.json());

  // CORS for development
  app.use((_req: Request, res: Response, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:5173');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
  });

  // Static dosyaları servis et
  const publicPath = getPublicPath();
  app.use(express.static(publicPath));

  // ── REST API ─────────────────────────────────────────────────

  // GET /api/status — daemon/server durumu
  app.get('/api/status', async (_req: Request, res: Response) => {
    try {
      const { getDaemonStatus } = await import('../daemon.js');
      const status = await getDaemonStatus({ port });
      res.json(status);
    } catch {
      res.json({
        running: true,
        pid: process.pid,
        uptime: process.uptime(),
        port,
        sessions: 0,
        startedAt: new Date().toISOString(),
      });
    }
  });

  // GET /api/sessions — aktif session listesi
  app.get('/api/sessions', async (_req: Request, res: Response) => {
    try {
      const { getActiveSessions } = await import('../daemon.js');
      const count = getActiveSessions();
      res.json({ sessions: count, count });
    } catch {
      res.json({ sessions: 0, count: 0 });
    }
  });

  // GET /api/stats — kullanım istatistikleri
  app.get('/api/stats', (_req: Request, res: Response) => {
    const stats = (webUIController as any).currentStats ?? {
      messages: 0,
      inputTokens: 0,
      outputTokens: 0,
      turns: 0,
      provider: 'unknown',
      model: 'unknown',
    };
    res.json(stats);
  });

  // POST /api/chat — mesaj gönder, cevap al
  app.post('/api/chat', (req: Request, res: Response) => {
    const { message, session: _session } = req.body ?? {};
    if (typeof message !== 'string' || !message.trim()) {
      res.status(400).json({ error: 'message alanı gereklidir.' });
      return;
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    // SSE wrapper: WebSocket broadcast'leri bu response'a yönlendir
    const send = (event: string, data: unknown) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    const origBroadcast = webUIController.broadcast.bind(webUIController);
    const apiOverride = (ev: { type: string; data: unknown }) => {
      origBroadcast(ev as any);
      send(ev.type, ev.data);
    };
    (webUIController as any)._apiBroadcast = apiOverride;

    webUIController.handleWebInput(message);

    // Timeout: 60 saniye sonra kapat
    const timeout = setTimeout(() => {
      send('done', { timeout: true });
      res.end();
    }, 60000);

    req.on('close', () => {
      clearTimeout(timeout);
      delete (webUIController as any)._apiBroadcast;
    });
  });

  // POST /api/abort — mevcut işlemi iptal et
  app.post('/api/abort', (_req: Request, res: Response) => {
    webUIController.handleWebAbort();
    res.json({ ok: true });
  });

  // ── WebSocket ─────────────────────────────────────────────────

  wss.on('connection', (ws: WS) => {
    console.log(chalk.cyan('  🌐 Web UI bağlandı.'));

    ws.on('message', (message: RawData) => {
      try {
        const event = JSON.parse(message.toString());
        if (event.type === 'user_input') {
          console.log(chalk.cyan(`\n  [Web UI] > ${event.data}`));
          webUIController.handleWebInput(event.data);
        } else if (event.type === 'command') {
          console.log(chalk.magenta(`\n  [Web CMD] > ${event.data}`));
          webUIController.handleWebCommand(event.data);
        } else if (event.type === 'abort') {
          console.log(chalk.red(`\n  [Web UI] > ABORT REQUEST`));
          webUIController.handleWebAbort();
        } else if (event.type === 'get_models') {
          webUIController.handleGetModels(event.data);
        } else if (event.type === 'open_in_editor') {
          const filePath = String(event.data?.path ?? '');
          if (filePath) {
            const vscodeCheck = spawnSync('which', ['code'], { encoding: 'utf-8' });
            const cmd = vscodeCheck.status === 0 ? 'code' : 'xdg-open';
            spawnAsync(cmd, [filePath], { detached: true, stdio: 'ignore' }).unref();
          }
        } else if (event.type === 'get_api_keys') {
          const status = webUIController.getApiKeyStatus();
          ws.send(JSON.stringify({ type: 'api_key_status', data: status }));
        } else if (event.type === 'set_api_key') {
          const { provider, apiKey } = event.data ?? {};
          if (provider && apiKey) {
            const result = webUIController.setApiKey(provider, apiKey);
            if (result.success) {
              ws.send(JSON.stringify({ type: 'api_key_saved', data: { provider } }));
            } else {
              ws.send(JSON.stringify({ type: 'api_key_error', data: { provider, error: result.error } }));
            }
          } else {
            ws.send(JSON.stringify({ type: 'api_key_error', data: { error: 'Provider ve API anahtarı gerekli' } }));
          }
        } else if (event.type === 'daemon_status_request') {
          getDaemonStatus(port).then((status) => {
            ws.send(JSON.stringify({ type: 'daemon_status', data: status }));
          });
        }
      } catch (err) {
        console.error('WebSocket mesaj hatası:', err);
      }
    });

    ws.on('close', () => {
      console.log(chalk.dim('  🌐 Web UI bağlantısı kesildi.'));
    });
  });

  return new Promise<void>((resolve: () => void, reject) => {
    server.listen(port, 'localhost', async () => {
      console.log(chalk.green(`\n  ✓ SETH Web Sunucusu çalışıyor: http://localhost:${port}`));
      try {
        await open(`http://localhost:${port}`);
      } catch {
        console.log(chalk.yellow(`  ⚠ Tarayıcı otomatik açılamadı. Lütfen şu adrese gidin: http://localhost:${port}`));
      }
      resolve();
    });
    server.on('error', (err) => {
      if ((err as any).code === 'EADDRINUSE') {
        console.log(chalk.yellow(`  ⚠ Port ${port} kullanımda, web sunucusu başlatılamadı.`));
        resolve();
      } else {
        reject(err);
      }
    });
  });
}

async function getDaemonStatus(port: number) {
  try {
    const { getDaemonStatus: _getDaemonStatus } = await import('../daemon.js');
    return await _getDaemonStatus({ port });
  } catch {
    return {
      running: true,
      pid: process.pid,
      uptime: Math.floor(process.uptime()),
      port,
      sessions: 0,
      startedAt: new Date().toISOString(),
    };
  }
}

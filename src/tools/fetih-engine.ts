import { z } from 'zod';
import { spawn, ChildProcess } from 'child_process';
import { existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import type { ToolDefinition, ToolResult } from '../types.js';

const __fetihDirname = dirname(fileURLToPath(import.meta.url));
const ENGINE_PATH = join(__fetihDirname, '../../FETIH-Apps/Core/FETIH_Engine.py');

let pythonWorker: ChildProcess | null = null;

function getWorker(): ChildProcess {
  if (pythonWorker) return pythonWorker;

  if (!existsSync(ENGINE_PATH)) {
    throw new Error(`FETIH Engine bulunamadı: ${ENGINE_PATH}`);
  }

  pythonWorker = spawn('python3', [ENGINE_PATH], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  if (pythonWorker.stdout) {
    pythonWorker.stdout.on('data', (data: Buffer) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed.type === 'log') {
            const color = parsed.level === 'SUCCESS' ? '\x1b[32m' : parsed.level === 'ERROR' ? '\x1b[31m' : '\x1b[36m';
            console.log(`${color}[FETIH-WORKER] [${parsed.timestamp}] [${parsed.level}] ${parsed.message}\x1b[0m`);
          }
        } catch {
          // JSON değilse yoksay
        }
      }
    });
  }

  pythonWorker.stderr?.on('data', (d: Buffer) => {
    process.stderr.write(`[FETIH-Engine] ${d}`);
  });

  pythonWorker.on('error', (e) => {
    process.stderr.write(`[FETIH-Engine] Başlatma hatası: ${e.message}\n`);
    pythonWorker = null;
  });

  pythonWorker.on('exit', () => { pythonWorker = null; });

  return pythonWorker;
}

export const fetihEngineSchema = z.object({
  target: z.string().describe('Operasyon yapılacak hedef IP veya domain'),
  action: z.enum(['nmap', 'nuclei', 'sqlmap', 'bypass_cloudflare', 'subdomain', 'whatweb', 'brute_force', 'dir_search', 'exploit_search', 'lateral_movement', 'config_audit', 'service_integrity', 'campaign', 'breach_query', 'get_map', 'exit']).describe('Yürütülecek siber operasyon eylemi'),
});

export async function fetihEngine(input: Record<string, unknown>): Promise<ToolResult> {
  const args = fetihEngineSchema.parse(input);
  const { target, action } = args;

  let worker: ChildProcess;
  try {
    worker = getWorker();
  } catch (e) {
    return { output: `FETIH Engine başlatılamadı: ${e instanceof Error ? e.message : String(e)}`, isError: true };
  }

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      worker.stdout?.removeListener('data', onData);
      resolve({ output: 'Zaman aşımı: FETIH Engine 60s içinde yanıt vermedi', isError: true });
    }, 60_000);

    const onData = (data: Buffer) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed.type === 'result') {
            clearTimeout(timeout);
            worker.stdout?.removeListener('data', onData);
            resolve({
              output: JSON.stringify(parsed, null, 2),
              isError: parsed.status === 'error',
            });
            return;
          }
        } catch {
          // Yanıt JSON değilse devam et
        }
      }
    };

    worker.stdout?.on('data', onData);
    if (worker.stdin) worker.stdin.write(JSON.stringify({ action, target }) + '\n');
  });
}

export const fetihEngineTool: ToolDefinition = {
  name: 'fetihEngine',
  description: 'FETIH Otonom Operasyon Motoru. Python Worker üzerinden Nmap, Nuclei ve Cloudflare Bypass araçlarını kontrol eder.',
  inputSchema: {
    type: 'object',
    properties: {
      target: { type: 'string', description: 'Operasyon yapılacak hedef IP veya domain' },
      action: {
        type: 'string',
        enum: ['nmap', 'nuclei', 'sqlmap', 'bypass_cloudflare', 'subdomain', 'whatweb', 'brute_force', 'dir_search', 'exploit_search', 'lateral_movement', 'config_audit', 'service_integrity', 'campaign', 'breach_query', 'get_map', 'exit'],
        description: 'Yürütülecek siber operasyon eylemi',
      },
    },
    required: ['target', 'action'],
  },
  execute: fetihEngine,
};

import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { createDaemonLogger, type DaemonLogger } from './daemon-log.js';

export interface DaemonConfig {
  port: number;
  host: string;
  pidFile: string;
  logFile: string;
  stateDir: string;
}

export interface DaemonStatus {
  running: boolean;
  pid: number | null;
  uptime: number | null;
  port: number;
  sessions: number;
  startedAt: string | null;
}

const DEFAULT_STATE_DIR = join(homedir(), '.fetih');

export function getDefaultConfig(overrides?: Partial<DaemonConfig>): DaemonConfig {
  const stateDir = overrides?.stateDir ?? DEFAULT_STATE_DIR;
  return {
    port: 4321,
    host: 'localhost',
    pidFile: join(stateDir, 'fetih.pid'),
    logFile: join(stateDir, 'daemon.log'),
    stateDir,
    ...overrides,
  };
}

export async function setupDaemonDirectories(stateDir: string): Promise<void> {
  if (!existsSync(stateDir)) {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  }
}

function writePid(pidFile: string, pid: number): void {
  writeFileSync(pidFile, String(pid), 'utf8');
}

function readPid(pidFile: string): number | null {
  if (!existsSync(pidFile)) return null;
  const raw = readFileSync(pidFile, 'utf8').trim();
  const pid = parseInt(raw, 10);
  return isNaN(pid) ? null : pid;
}

function removePid(pidFile: string): void {
  if (existsSync(pidFile)) {
    try { unlinkSync(pidFile); } catch { /* ignore */ }
  }
}

function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

let daemonStartedAt: Date | null = null;
let activeSessions = 0;
let daemonLogger: DaemonLogger | null = null;

export function getDaemonLogger(): DaemonLogger | null {
  return daemonLogger;
}

export function incrementSessions(): void { activeSessions++; }
export function decrementSessions(): void { activeSessions = Math.max(0, activeSessions - 1); }
export function getActiveSessions(): number { return activeSessions; }

export async function isDaemonRunning(pidFile?: string): Promise<boolean> {
  const cfg = getDefaultConfig(pidFile ? { pidFile } : {});
  const pid = readPid(cfg.pidFile);
  if (pid === null) return false;
  return isProcessRunning(pid);
}

export async function getDaemonStatus(config?: Partial<DaemonConfig>): Promise<DaemonStatus> {
  const cfg = getDefaultConfig(config);
  const pid = readPid(cfg.pidFile);

  if (pid === null || !isProcessRunning(pid)) {
    return {
      running: false,
      pid: null,
      uptime: null,
      port: cfg.port,
      sessions: 0,
      startedAt: null,
    };
  }

  const uptime = daemonStartedAt
    ? Math.floor((Date.now() - daemonStartedAt.getTime()) / 1000)
    : null;

  return {
    running: true,
    pid,
    uptime,
    port: cfg.port,
    sessions: activeSessions,
    startedAt: daemonStartedAt?.toISOString() ?? null,
  };
}

export async function startDaemon(config?: Partial<DaemonConfig>): Promise<void> {
  const cfg = getDefaultConfig(config);

  await setupDaemonDirectories(cfg.stateDir);

  const logger = createDaemonLogger(cfg.logFile);
  daemonLogger = logger;

  // Check if already running
  const pid = readPid(cfg.pidFile);
  if (pid !== null && isProcessRunning(pid)) {
    logger.warn(`Daemon already running with PID ${pid}`);
    console.log(`FETIH daemon zaten çalışıyor (PID: ${pid})`);
    return;
  }

  process.title = 'fetih-daemon';
  daemonStartedAt = new Date();
  writePid(cfg.pidFile, process.pid);

  logger.info(`FETIH daemon başlatılıyor... PID: ${process.pid}`);

  // Web UI v4.x'te kaldırıldı. Daemon sadece arka plan engine olarak çalışır.

  // FETIH engine'i başlat (provider, tools, callback'ler)
  const { initializeDaemonHandler } = await import('./daemon-handler.js');
  await initializeDaemonHandler();

  const shutdown = async (signal: string) => {
    logger.info(`${signal} alındı, graceful shutdown başlıyor...`);
    removePid(cfg.pidFile);
    logger.info('Daemon durduruldu.');
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGHUP', () => {
    logger.info('SIGHUP alındı - daemon yeniden başlatılıyor...');
    // Could reload config here
  });

  logger.info(`Daemon hazır. PID: ${process.pid}`);
}

export async function stopDaemon(config?: Partial<DaemonConfig>): Promise<void> {
  const cfg = getDefaultConfig(config);
  const pid = readPid(cfg.pidFile);

  if (pid === null) {
    console.log('FETIH daemon çalışmıyor (PID dosyası bulunamadı).');
    return;
  }

  if (!isProcessRunning(pid)) {
    console.log(`FETIH daemon çalışmıyor. Eski PID dosyası temizleniyor...`);
    removePid(cfg.pidFile);
    return;
  }

  console.log(`FETIH daemon durduruluyor (PID: ${pid})...`);
  try {
    process.kill(pid, 'SIGTERM');
  } catch (err) {
    console.error(`SIGTERM gönderilemedi: ${err}`);
    return;
  }

  // 5 saniye bekle, sonra SIGKILL
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 200));
    if (!isProcessRunning(pid)) {
      removePid(cfg.pidFile);
      console.log('FETIH daemon başarıyla durduruldu.');
      return;
    }
  }

  console.log('Daemon SIGTERM\'e yanıt vermedi, SIGKILL gönderiliyor...');
  try {
    process.kill(pid, 'SIGKILL');
  } catch { /* already dead */ }
  removePid(cfg.pidFile);
  console.log('FETIH daemon zorla durduruldu.');
}

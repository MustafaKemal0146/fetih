import { appendFileSync, mkdirSync, existsSync } from 'fs';
import { dirname } from 'path';

export type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'DEBUG';

export interface DaemonLogger {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
  debug: (msg: string) => void;
}

function formatTimestamp(): string {
  return new Date().toISOString();
}

function writeLog(logFile: string, level: LogLevel, msg: string): void {
  const line = `[${formatTimestamp()}] [${level}] ${msg}\n`;
  try {
    const dir = dirname(logFile);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    appendFileSync(logFile, line, 'utf8');
  } catch {
    // Log write errors are non-fatal
  }
}

export function createDaemonLogger(logFile: string): DaemonLogger {
  return {
    info: (msg: string) => writeLog(logFile, 'INFO', msg),
    warn: (msg: string) => writeLog(logFile, 'WARN', msg),
    error: (msg: string) => writeLog(logFile, 'ERROR', msg),
    debug: (msg: string) => writeLog(logFile, 'DEBUG', msg),
  };
}

/**
 * lifecycle stub — MCP bridge modunda graceful shutdown.
 * interactive-session ve pwn-session araçları bu modülü import eder.
 */

type CleanupFn = () => void | Promise<void>;

const cleanupFns: CleanupFn[] = [];
let registered = false;

export function registerCleanup(fn: CleanupFn): void {
  cleanupFns.push(fn);
}

export function setupGracefulShutdown(): void {
  if (registered) return;
  registered = true;

  const shutdown = async () => {
    for (const fn of cleanupFns) {
      try { await fn(); } catch { /* sessizce geç */ }
    }
    process.exit(0);
  };

  process.on('SIGTERM', () => { void shutdown(); });
}

export async function startBackgroundCleanup(_sessionsDir: string): Promise<void> {
  // MCP bridge modunda kullanılmaz
}

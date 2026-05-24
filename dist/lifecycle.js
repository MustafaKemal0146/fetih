/**
 * lifecycle stub — MCP bridge modunda graceful shutdown.
 * interactive-session ve pwn-session araçları bu modülü import eder.
 */
const cleanupFns = [];
let registered = false;
export function registerCleanup(fn) {
    cleanupFns.push(fn);
}
export function setupGracefulShutdown() {
    if (registered)
        return;
    registered = true;
    const shutdown = async () => {
        for (const fn of cleanupFns) {
            try {
                await fn();
            }
            catch { /* sessizce geç */ }
        }
        process.exit(0);
    };
    process.on('SIGTERM', () => { void shutdown(); });
}
export async function startBackgroundCleanup(_sessionsDir) {
    // MCP bridge modunda kullanılmaz
}

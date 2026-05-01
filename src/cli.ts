#!/usr/bin/env node

/**
 * @fileoverview SETH CLI entry point.
 */

import type { ProviderName, SETHConfig } from './types.js';
import { VERSION } from './version.js';
import chalk from 'chalk';

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  let prompt: string | undefined;
  let providerArg: ProviderName | undefined;
  let modelArg: string | undefined;
  let debug = false;
  let noTools = false;
  let autoApprove = false;
  let resumeId: string | undefined;
  let daemonMode = false;
  let daemonPort: number | undefined;

  // daemon subcommand: seth daemon start|stop|status|restart
  if (args[0] === 'daemon') {
    const subCmd = args[1];
    const portIdx = args.indexOf('--port');
    const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : undefined;

    const { startDaemon, stopDaemon, getDaemonStatus } = await import('./daemon.js');

    switch (subCmd) {
      case 'start':
        await startDaemon(port ? { port } : {});
        break;
      case 'stop':
        await stopDaemon(port ? { port } : {});
        break;
      case 'status': {
        const status = await getDaemonStatus(port ? { port } : {});
        if (status.running) {
          console.log(chalk.green(`SETH daemon çalışıyor`));
          console.log(`  PID:       ${status.pid}`);
          console.log(`  Port:      ${status.port}`);
          console.log(`  Uptime:    ${status.uptime}s`);
          console.log(`  Sessions:  ${status.sessions}`);
          console.log(`  Başlama:   ${status.startedAt}`);
        } else {
          console.log(chalk.red('SETH daemon çalışmıyor.'));
        }
        break;
      }
      case 'restart': {
        await stopDaemon(port ? { port } : {});
        await new Promise((r) => setTimeout(r, 1000));
        await startDaemon(port ? { port } : {});
        break;
      }
      default:
        console.log('Kullanım: seth daemon <start|stop|status|restart> [--port PORT]');
    }
    return;
  }

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '-p':
      case '--prompt':
        prompt = args[++i];
        break;
      case '--provider':
        providerArg = args[++i] as ProviderName;
        break;
      case '--model':
        modelArg = args[++i];
        break;
      case '--debug':
        debug = true;
        break;
      case '-y':
      case '--auto':
        autoApprove = true;
        break;
      case '--resume':
        resumeId = args[++i];
        break;
      case '-d':
      case '--daemon':
        daemonMode = true;
        break;
      case '--port':
        daemonPort = parseInt(args[++i], 10);
        break;
      case '-v':
      case '--version':
        console.log(`seth v${VERSION}`);
        process.exit(0);
        break;
      case '-u':
      case '--update':
        (async () => {
          const { performSelfUpdate } = await import('./update-check.js');
          console.log(chalk.cyan('🔄 SETH Self-Update başlatılıyor...\n'));
          const result = await performSelfUpdate((msg) => console.log(chalk.dim(`  ${msg}`)));
          console.log('');
          if (result.success && result.method !== 'none') {
            console.log(chalk.green(`✅ ${result.message.split('\n')[0]}`));
            console.log(chalk.cyan(`  v${result.previousVersion} → v${result.newVersion}`));
          } else {
            console.log(result.success ? chalk.green(result.message) : chalk.red(result.message));
          }
        })().catch((err) => {
          console.error(chalk.red(`❌ Güncelleme hatası: ${err.message}`));
          process.exit(1);
        });
        break;
    }
  }

  // --daemon flag: daemon olarak başlat
  if (daemonMode) {
    const { startDaemon } = await import('./daemon.js');
    await startDaemon(daemonPort ? { port: daemonPort } : {});
    return;
  }

  const configOverrides: { -readonly [K in keyof SETHConfig]?: SETHConfig[K] } = { debug, autoApprove };
  if (providerArg) configOverrides.defaultProvider = providerArg as ProviderName;
  if (modelArg) configOverrides.defaultModel = modelArg;

  // v3.9.5: Yeni modülleri başlat
  const { loadConfig } = await import('./config/settings.js');
  const cfg = loadConfig(configOverrides);
  const { initNewModules } = await import('./init-modules.js');
  await initNewModules(cfg);

  if (prompt) {
    const { runHeadless } = await import('./headless.js');
    await runHeadless(prompt, { provider: providerArg, model: modelArg, noTools, debug, autoApprove });
  } else {
    const { runOnboardingIfNeeded } = await import('./onboarding.js');
    await runOnboardingIfNeeded();

    const { resolveModel } = await import('./config/settings.js');
    
    const { playIntro } = await import('./intro.js');
    await playIntro(cfg.defaultProvider, resolveModel(cfg.defaultProvider, cfg, modelArg), '');

    // Ink (React) UI yerine eski stabil REPL'e geri dönüyoruz
    const { startRepl } = await import('./repl.js');
    await startRepl(configOverrides, true, resumeId, '');
  }
}

main().catch((err) => {
  console.error(chalk.red(`Fatal: ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
});

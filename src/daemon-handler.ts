/**
 * @fileoverview Daemon handler — FETIH engine'i web UI için başlatır.
 * Daemon modunda REPL olmadan agent loop'u web'den yönetir.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import chalk from 'chalk';
import { createProvider } from './providers/base.js';
import { loadConfig, resolveModel } from './config/settings.js';
import { createDefaultRegistry, ToolRegistry } from './tools/registry.js';
import { ToolExecutor } from './tools/executor.js';
import { createSession, saveSession } from './storage/session.js';
import { runAgentLoop, type AgentLoopOptions } from './agent/loop.js';
import { webUIController } from './web/controller.js';
import { getDaemonLogger } from './daemon.js';
import type { ProviderName, FetihConfig, ChatMessage, LLMProvider, SessionData } from './types.js';
import { buildSystemPrompt } from './project-instructions.js';

let daemonProvider: LLMProvider | null = null;
let daemonModel: string = '';
let daemonToolRegistry: ToolRegistry | null = null;
let daemonToolExecutor: ToolExecutor | null = null;
let daemonSession: SessionData | null = null;
let daemonConfig: FetihConfig | null = null;
let daemonProcessing = false;
let daemonAbortController: AbortController | null = null;
let daemonCurrentCwd = process.cwd();
let daemonEffort = 'medium';

export async function initializeDaemonHandler(): Promise<void> {
  const logger = getDaemonLogger();
  logger?.info('FETIH engine başlatılıyor...');

  const { setupGracefulShutdown, startBackgroundCleanup } = await import('./lifecycle.js');
  setupGracefulShutdown();
  void startBackgroundCleanup(join(homedir(), '.fetih', 'sessions'));

  // Fetih Engine arka plan sunucusunu başlat
  const { startSethEngine } = await import('./fetih-engine/bridge.js');
  startSethEngine();

  daemonConfig = loadConfig();

  daemonModel = resolveModel(daemonConfig.defaultProvider as ProviderName, daemonConfig);

  try {
    daemonProvider = await createProvider(daemonConfig.defaultProvider as ProviderName, daemonConfig);
  } catch (err) {
    logger?.error(`Provider başlatılamadı: ${err instanceof Error ? err.message : String(err)}`);
    console.error(chalk.red(`✗ Provider başlatılamadı: ${err}`));
    return;
  }

  daemonToolRegistry = await createDefaultRegistry();
  const confirmFn = daemonConfig.autoApprove ? async () => true : undefined;
  daemonToolExecutor = new ToolExecutor(daemonToolRegistry, daemonConfig.tools, confirmFn);

  daemonSession = createSession(daemonConfig.defaultProvider as ProviderName, daemonModel);

  // Auto-memory
  import('./auto-memory.js').then(({ ensureProjectMetadata }) => {
    ensureProjectMetadata(daemonCurrentCwd, daemonProvider!, daemonModel).catch(() => {});
  }).catch(() => {});

  // ── Web UI callback'lerini bağla ───────────────────────────────

  webUIController.onUserInput((text: string) => {
    if (!daemonProcessing && daemonProvider && daemonToolExecutor && daemonToolRegistry) {
      runDaemonAgentTurn(text).catch((err) => {
        const logger = getDaemonLogger();
        logger?.error(`Agent turn hatası: ${err instanceof Error ? err.message : String(err)}`);
      });
    }
  });

  webUIController.onWebAbort(() => {
    if (daemonAbortController) {
      daemonAbortController.abort();
      daemonAbortController = null;
    }
  });

  webUIController.onWebCommand(async (text: string) => {
    if (daemonProcessing) {
      webUIController.sendCommandResult('⚠ İşlem devam ediyor, komut şu an çalıştırılamaz.');
      return;
    }
    // Temel komutları çalıştır
    try {
      let result = '';
      const cmd = text.trim().toLowerCase();

      if (cmd === 'status') {
        const { getDaemonStatus } = await import('./daemon.js');
        const status = await getDaemonStatus({ port: 4321 });
        result = `Daemon: ${status.running ? '✅ Çalışıyor' : '❌ Durdu'}\nPID: ${status.pid}\nUptime: ${status.uptime ?? 0}s\nSession: ${status.sessions}`;
      } else if (cmd.startsWith('model ')) {
        const modelName = cmd.slice(6).trim();
        if (modelName) {
          daemonModel = modelName;
          daemonProvider = await createProvider(daemonConfig!.defaultProvider as ProviderName, daemonConfig!);
          daemonSession = createSession(daemonConfig!.defaultProvider as ProviderName, daemonModel);
          result = `✅ Model değiştirildi: ${modelName}`;
        } else {
          result = `Mevcut model: ${daemonModel}`;
        }
      } else if (cmd.startsWith('sağlayıcı') || cmd.startsWith('saglayici') || cmd.startsWith('/sağlayıcı') || cmd.startsWith('/saglayici')) {
        const args = text.replace(/^\/?sağlayıcı|^\/?saglayici/i, '').trim();
        const parts = args.split(/\s+/);
        const providerName = parts[0]?.toLowerCase();
        const modelName = parts.slice(1).join(' ').trim() || null;

        if (!providerName) {
          result = `Mevcut provider: ${daemonConfig?.defaultProvider}\nMevcut model: ${daemonModel}\nKullanım: /sağlayıcı [provider_adı] [model]\nProviderlar: deepseek, anthropic, google, openai, ollama, nvidia`;
        } else {
          const validProviders = ['deepseek', 'anthropic', 'google', 'openai', 'ollama', 'nvidia'];
          if (!validProviders.includes(providerName)) {
            result = `❌ Geçersiz provider: ${providerName}. Geçerli: ${validProviders.join(', ')}`;
          } else {
            const newConfig = loadConfig({ defaultProvider: providerName as ProviderName });
            daemonConfig = newConfig;
            daemonModel = modelName || resolveModel(providerName as ProviderName, newConfig);
            daemonProvider = await createProvider(providerName as ProviderName, newConfig);
            daemonSession = createSession(providerName as ProviderName, daemonModel);
            result = `✅ Provider değiştirildi: ${providerName}\n✅ Model: ${daemonModel}`;
          }
        }
      } else {
        result = `Bilinmeyen komut: ${text}. Desteklenen: status, model, sağlayıcı`;
      }

      webUIController.sendCommandResult(result);
    } catch (err: any) {
      webUIController.sendCommandResult(`✗ ${err?.message ?? String(err)}`);
    }
  });

  webUIController.onGetModels(async (provider: string) => {
    try {
      const { listModels } = await import('./providers/factory.js');
      const p = provider as ProviderName;
      const models = await listModels(p, daemonConfig?.providers?.[p]);
      webUIController.sendModels(provider, models);
    } catch {
      webUIController.sendModels(provider, []);
    }
  });

  // Mevcut ayarları yayınla
  webUIController.sendEffort(daemonEffort);
  webUIController.sendSettings({
    permissionLevel: daemonToolExecutor?.getPermissionLevel() ?? 'normal',
    securityProfile: daemonToolExecutor?.getSecurityProfile() ?? 'standard',
    theme: daemonConfig?.theme ?? 'dark',
  });

  // Mevcut istatistikleri yayınla
  webUIController.sendStats({
    messages: (daemonSession?.messages ?? []).length,
    inputTokens: 0,
    outputTokens: 0,
    turns: 0,
    provider: daemonConfig?.defaultProvider ?? 'unknown',
    model: daemonModel,
  });

  webUIController.sendStatus('ready', false);

  logger?.info(`FETIH engine hazır. Provider: ${daemonConfig?.defaultProvider}, Model: ${daemonModel}`);
  console.log(chalk.green(`  ✓ FETIH engine hazır: ${daemonConfig?.defaultProvider} / ${daemonModel}`));
}

async function runDaemonAgentTurn(text: string): Promise<void> {
  if (!daemonProvider || !daemonToolExecutor || !daemonToolRegistry || !daemonConfig || !daemonSession) return;

  const controller = new AbortController();
  daemonAbortController = controller;
  daemonProcessing = true;

  const logger = getDaemonLogger();
  logger?.info(`Agent turn başladı: "${text.slice(0, 100)}"`);

  webUIController.sendStatus('processing', true);

  // Kullanıcı mesajını session'a ekle
  daemonSession.messages.push({ role: 'user', content: text });

  try {
    const systemPrompt = buildSystemPrompt(daemonCurrentCwd);
    const planModePrompt = ''; // Daemon modunda plan modu yok (opsiyonel)

    const loopOptions: AgentLoopOptions = {
      provider: daemonProvider,
      model: daemonModel,
      systemPrompt: planModePrompt || systemPrompt,
      toolRegistry: daemonToolRegistry,
      toolExecutor: daemonToolExecutor,
      maxTurns: daemonConfig.agent.maxTurns,
      maxTokens: daemonConfig.agent.maxTokens,
      cwd: daemonCurrentCwd,
      debug: daemonConfig.debug,
      effort: daemonEffort,
      abortSignal: controller.signal,
      maxConcurrentTools: 5,
      onText: (chunk: string) => {
        webUIController.sendText(chunk);
      },
      onToolCall: (name: string, input: Record<string, unknown>) => {
        webUIController.sendToolCall(name, input);
        logger?.info(`Tool çağrısı: ${name}`);
      },
      onToolResult: (name: string, output: string, isError: boolean) => {
        webUIController.sendToolResult(name, output, isError);
      },
      onTruncation: (toolName: string) => {
        webUIController.sendWarning(`Araç çıktısı kesildi: ${toolName}`, toolName);
      },
    };

    const result = await runAgentLoop(text, daemonSession.messages, loopOptions);

    // Session'u güncelle
    daemonSession.messages.splice(0, daemonSession.messages.length, ...result.messages);

    // İstatistikleri yayınla
    webUIController.sendStats({
      messages: result.messages.length,
      inputTokens: result.totalUsage.inputTokens,
      outputTokens: result.totalUsage.outputTokens,
      turns: result.turns,
      provider: daemonConfig.defaultProvider ?? 'unknown',
      model: daemonModel,
    });

    // Session'u kaydet
    const sessionToSave = {
      ...daemonSession,
      tokenUsage: { inputTokens: result.totalUsage.inputTokens, outputTokens: result.totalUsage.outputTokens },
      updatedAt: new Date().toISOString(),
      messages: result.messages,
    };
    saveSession(sessionToSave as SessionData);

    logger?.info(`Agent turn tamamlandı. Tur: ${result.turns}, Token: ${result.totalUsage.inputTokens + result.totalUsage.outputTokens}`);
  } catch (err: any) {
    if (err?.name === 'AbortError' || controller.signal.aborted) {
      logger?.info('Agent turn iptal edildi.');
    } else {
      logger?.error(`Agent turn hatası: ${err?.message ?? String(err)}`);
      webUIController.sendWarning(`Hata: ${err?.message ?? String(err)}`);
    }
  } finally {
    daemonProcessing = false;
    daemonAbortController = null;
    webUIController.sendStatus('idle', false);
  }
}

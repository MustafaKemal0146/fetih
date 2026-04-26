/**
 * @fileoverview SETH v3.9.5 — Tüm yeni modüllerin inisiyalizasyonu.
 * AGPL-3.0
 */

import type { SETHConfig } from './types.js';

export async function initNewModules(config: SETHConfig): Promise<void> {
  // 1. Güvenlik denetimi — en önce başlamalı
  const { initSecurity } = await import('./security/index.js');
  initSecurity(config);

  // 2. Görev sistemi
  const { initTaskSystem, registerCronTasks } = await import('./tasks/index.js');
  initTaskSystem();

  // 3. Eski cron görevlerini task sistemine aktar
  registerCronTasks();

  // 4. Sandbox
  const { initSandbox } = await import('./sandbox/index.js');
  initSandbox();

  // 5. Context Engine
  const { initContextEngine } = await import('./context-engine/index.js');
  initContextEngine({
    maxTokens: config.contextBudgetTokens || 200_000,
    compressionEnabled: true,
  });

  // 6. Auto-Reply
  const { initAutoReply, setEnabled } = await import('./auto-reply/index.js');
  initAutoReply();
  // Auto-Reply varsayılan olarak kapalı, /autoreply komutu ile açılır

  // 7. Akışlar
  const { initFlows } = await import('./flows/index.js');
  initFlows();

  // 8. Plugin dizini hazır (plugin'ler registry.ts'de ayrıca yükleniyor)
  const { getPluginDir } = await import('./plugin/index.js');
  getPluginDir();
}

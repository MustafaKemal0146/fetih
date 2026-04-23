/**
 * @fileoverview Multi-Agent Koordinatör — karmaşık görevleri alt ajanlara böler ve paralel çalıştırır.
 * Koordinatör önce görevi alt görevlere ayırır, sonra her birini agent_spawn ile paralel çalıştırır.
 */

import type { LLMProvider, ChatMessage } from '../types.js';
import { runAgentLoop } from './loop.js';
import { createDefaultRegistry } from '../tools/registry.js';
import { ToolExecutor } from '../tools/executor.js';
import { loadConfig } from '../config/settings.js';
import { buildSystemPrompt } from '../project-instructions.js';

export interface CoordinatorTask {
  id: number;
  title: string;
  description: string;
}

export interface CoordinatorResult {
  tasks: CoordinatorTask[];
  results: Array<{ taskId: number; output: string; success: boolean }>;
  summary: string;
}

const COORDINATOR_SYSTEM_PROMPT = `Sen bir koordinatör ajansın. Görevini şu adımlarla yönet:

1. Görevi analiz et
2. Bağımsız alt görevlere ayır (2-5 arası, birbirine bağımlı olmayan)
3. Her alt görevi agent_spawn ile paralel olarak çalıştır
4. Sonuçları birleştir ve özet sun

Alt görevleri agent_spawn aracıyla başlatırken şunlara dikkat et:
- Her alt görev tam ve bağımsız olmalı
- Alt görevler birbirinin sonucuna bağlı olmamalı
- Her alt goreve yeterli bağlam ver`;

/**
 * Koordinatör modunu başlat.
 * Görevi alt görevlere böler ve her birini agent_spawn ile çalıştırır.
 */
export async function runCoordinator(
  task: string,
  provider: LLMProvider,
  model: string,
  cwd: string,
  onText?: (text: string) => void,
): Promise<CoordinatorResult> {
  const config = loadConfig();
  const toolRegistry = await createDefaultRegistry(config);
  const toolExecutor = new ToolExecutor(toolRegistry, config.tools, async () => true);
  toolExecutor.setSecurityProfile(config.tools.securityProfile ?? 'standard');

  const systemPrompt = COORDINATOR_SYSTEM_PROMPT + '\n\n' + buildSystemPrompt(cwd);

  const coordinatorMessage =
    `KOORDİNATÖR MODU AKTİF\n\n` +
    `Görev: ${task}\n\n` +
    `Bu görevi 2-5 bağımsız alt göreve böl ve her birini agent_spawn aracıyla paralel çalıştır. ` +
    `Tüm alt görevler tamamlandıktan sonra sonuçları birleştirerek kapsamlı bir özet sun.`;

  const result = await runAgentLoop(coordinatorMessage, [], {
    provider,
    model,
    systemPrompt,
    toolRegistry,
    toolExecutor,
    maxTurns: 20,
    maxTokens: 1_000_000,
    cwd,
    debug: false,
    onText,
  });

  return {
    tasks: [],
    results: [],
    summary: result.finalText,
  };
}

import { getAgentSpawnDepth } from '../tools/agent-spawn.js';

/**
 * Aktif sub-agent sayısını al.
 */
export function getActiveSubAgentCount(): number {
  return getAgentSpawnDepth();
}

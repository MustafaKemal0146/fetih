/**
 * @fileoverview SETH Token/Maliyet Takibi — v3.9.6
 * AGPL-3.0
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { TokenUsage } from '../types.js';

const USAGE_FILE = join(homedir(), '.seth', 'usage.json');

interface UsageRecord {
  timestamp: string;
  sessionId: string;
  inputTokens: number;
  outputTokens: number;
  model: string;
  provider: string;
}

interface UsageStats {
  records: UsageRecord[];
}

const DEFAULT_PRICES: Record<string, { input: number; output: number }> = {
  'claude-sonnet-4-20250514': { input: 0.000003, output: 0.000015 },
  'claude-3-5-sonnet': { input: 0.000003, output: 0.000015 },
  'gemini-2.5-pro': { input: 0.00000125, output: 0.000005 },
  'gpt-4o': { input: 0.0000025, output: 0.00001 },
  'deepseek-chat': { input: 0.0000003, output: 0.0000015 },
  'qwen3-coder': { input: 0.0000005, output: 0.000002 },
};

function getPrice(model: string): { input: number; output: number } {
  for (const [key, price] of Object.entries(DEFAULT_PRICES)) {
    if (model.includes(key)) return price;
  }
  return { input: 0.000003, output: 0.000015 }; // varsayılan
}

function ensureFile(): void {
  const dir = join(homedir(), '.seth');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  if (!existsSync(USAGE_FILE)) {
    writeFileSync(USAGE_FILE, JSON.stringify({ records: [] }), 'utf-8');
  }
}

function loadUsage(): UsageStats {
  ensureFile();
  try { return JSON.parse(readFileSync(USAGE_FILE, 'utf-8')); }
  catch { return { records: [] }; }
}

function saveUsage(stats: UsageStats): void {
  ensureFile();
  writeFileSync(USAGE_FILE, JSON.stringify(stats, null, 2), 'utf-8');
}

let currentSessionId: string | null = null;

export function setSessionId(id: string): void {
  currentSessionId = id;
}

export function logUsage(usage: TokenUsage, model: string, provider: string): void {
  const stats = loadUsage();
  stats.records.push({
    timestamp: new Date().toISOString(),
    sessionId: currentSessionId || 'unknown',
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
    model,
    provider,
  });
  // Son 10000 kaydı tut
  if (stats.records.length > 10000) {
    stats.records = stats.records.slice(-10000);
  }
  saveUsage(stats);
}

export function getUsageStats(): {
  totalInput: number;
  totalOutput: number;
  totalTokens: number;
  recordCount: number;
  sessionCount: number;
} {
  const stats = loadUsage();
  const totalInput = stats.records.reduce((s, r) => s + r.inputTokens, 0);
  const totalOutput = stats.records.reduce((s, r) => s + r.outputTokens, 0);
  const sessions = new Set(stats.records.map(r => r.sessionId));

  return {
    totalInput,
    totalOutput,
    totalTokens: totalInput + totalOutput,
    recordCount: stats.records.length,
    sessionCount: sessions.size,
  };
}

export function getCostEstimate(): {
  totalCostUSD: number;
  inputCost: number;
  outputCost: number;
  byModel: Record<string, number>;
} {
  const stats = loadUsage();
  let totalCost = 0;
  let inputCost = 0;
  let outputCost = 0;
  const byModel: Record<string, number> = {};

  for (const record of stats.records) {
    const price = getPrice(record.model);
    const inCost = record.inputTokens * price.input;
    const outCost = record.outputTokens * price.output;
    const total = inCost + outCost;

    inputCost += inCost;
    outputCost += outCost;
    totalCost += total;
    byModel[record.model] = (byModel[record.model] || 0) + total;
  }

  return { totalCostUSD: totalCost, inputCost, outputCost, byModel };
}

export function getSessionUsage(sessionId: string): {
  tokens: number;
  cost: number;
} {
  const stats = loadUsage();
  const sessionRecords = stats.records.filter(r => r.sessionId === sessionId);
  const totalTokens = sessionRecords.reduce((s, r) => s + r.inputTokens + r.outputTokens, 0);
  let totalCost = 0;

  for (const record of sessionRecords) {
    const price = getPrice(record.model);
    totalCost += record.inputTokens * price.input + record.outputTokens * price.output;
  }

  return { tokens: totalTokens, cost: totalCost };
}

export function clearUsage(): void {
  saveUsage({ records: [] });
}

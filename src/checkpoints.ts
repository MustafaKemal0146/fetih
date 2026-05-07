/**
 * @fileoverview Checkpoint sistemi — konuşmayı istediğin ana kaydet, geri dön.
 */

import { existsSync, writeFileSync, readFileSync, mkdirSync, readdirSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { ChatMessage, TokenUsage } from './types.js';

const CHECKPOINTS_DIR = join(homedir(), '.fetih', 'checkpoints');

export interface CheckpointData {
  name: string;
  sessionId: string;
  messages: ChatMessage[];
  messagesLaneB: ChatMessage[];
  activeLane: 'a' | 'b';
  tokenUsage: TokenUsage;
  savedAt: string;
}

function getSessionDir(sessionId: string): string {
  return join(CHECKPOINTS_DIR, sessionId.slice(0, 8));
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export function saveCheckpoint(
  sessionId: string,
  name: string,
  messages: ChatMessage[],
  messagesLaneB: ChatMessage[],
  activeLane: 'a' | 'b',
  tokenUsage: TokenUsage,
): void {
  const dir = getSessionDir(sessionId);
  ensureDir(dir);
  const safe = name.replace(/[^a-zA-Z0-9_\-ğüşıöçĞÜŞİÖÇ]/g, '_').slice(0, 64);
  const data: CheckpointData = {
    name: safe,
    sessionId,
    messages,
    messagesLaneB,
    activeLane,
    tokenUsage,
    savedAt: new Date().toISOString(),
  };
  writeFileSync(join(dir, `${safe}.json`), JSON.stringify(data, null, 2), 'utf-8');
}

export function loadCheckpoint(sessionId: string, name: string): CheckpointData | null {
  const dir = getSessionDir(sessionId);
  const safe = name.replace(/[^a-zA-Z0-9_\-ğüşıöçĞÜŞİÖÇ]/g, '_').slice(0, 64);
  const file = join(dir, `${safe}.json`);
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, 'utf-8')) as CheckpointData;
  } catch { return null; }
}

export function listCheckpoints(sessionId: string): Array<{ name: string; savedAt: string; messages: number }> {
  const dir = getSessionDir(sessionId);
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        try {
          const data = JSON.parse(readFileSync(join(dir, f), 'utf-8')) as CheckpointData;
          return { name: data.name, savedAt: data.savedAt, messages: data.messages.length };
        } catch { return null; }
      })
      .filter((x): x is { name: string; savedAt: string; messages: number } => x !== null)
      .sort((a, b) => a.savedAt.localeCompare(b.savedAt));
  } catch { return []; }
}

export function deleteCheckpoint(sessionId: string, name: string): boolean {
  const dir = getSessionDir(sessionId);
  const safe = name.replace(/[^a-zA-Z0-9_\-ğüşıöçĞÜŞİÖÇ]/g, '_').slice(0, 64);
  const file = join(dir, `${safe}.json`);
  if (!existsSync(file)) return false;
  try { unlinkSync(file); return true; } catch { return false; }
}

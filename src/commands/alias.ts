/**
 * @fileoverview SETH Hızlı Alias Sistemi — v3.9.6
 * AGPL-3.0
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const ALIAS_FILE = join(homedir(), '.seth', 'aliases.json');

interface AliasEntry {
  icerik: string;
  aciklama?: string;
  createdAt: string;
}

function ensureFile(): void {
  const dir = join(homedir(), '.seth');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  if (!existsSync(ALIAS_FILE)) writeFileSync(ALIAS_FILE, '{}', 'utf-8');
}

function loadAliases(): Record<string, AliasEntry> {
  ensureFile();
  try { return JSON.parse(readFileSync(ALIAS_FILE, 'utf-8')); }
  catch { return {}; }
}

function saveAliases(aliases: Record<string, AliasEntry>): void {
  ensureFile();
  writeFileSync(ALIAS_FILE, JSON.stringify(aliases, null, 2), 'utf-8');
}

export function setAlias(name: string, icerik: string, aciklama?: string): void {
  const aliases = loadAliases();
  aliases[name.toLowerCase()] = { icerik, aciklama, createdAt: new Date().toISOString() };
  saveAliases(aliases);
}

export function getAlias(name: string): string | null {
  const aliases = loadAliases();
  const entry = aliases[name.toLowerCase()];
  return entry ? entry.icerik : null;
}

export function deleteAlias(name: string): boolean {
  const aliases = loadAliases();
  const key = name.toLowerCase();
  if (!aliases[key]) return false;
  delete aliases[key];
  saveAliases(aliases);
  return true;
}

export function listAliases(): Array<{ name: string } & AliasEntry> {
  const aliases = loadAliases();
  return Object.entries(aliases).map(([name, entry]) => ({ name, ...entry }));
}

export function resolveAlias(input: string): { isAlias: boolean; resolved: string } {
  const trimmed = input.trim();
  if (trimmed.startsWith('/')) {
    const aliasName = trimmed.slice(1).split(' ')[0];
    const rest = trimmed.slice(aliasName.length + 2).trim();
    const content = getAlias(aliasName);
    if (content) {
      return { isAlias: true, resolved: rest ? `${content}\n\n${rest}` : content };
    }
  }
  return { isAlias: false, resolved: input };
}

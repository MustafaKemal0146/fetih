/**
 * @fileoverview FETIH Prompt Şablon Kütüphanesi — v3.9.6
 * AGPL-3.0
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const TEMPLATES_FILE = join(homedir(), '.fetih', 'templates.json');

interface TemplateEntry {
  prompt: string;
  aciklama: string;
}

const DEFAULT_TEMPLATES: Record<string, TemplateEntry> = {
  commit: {
    prompt: 'Git diff\'ini analiz et ve anlamlı bir commit mesajı yaz. Geleneksel commit formatını kullan (feat:, fix:, docs:, refactor:, test:, chore:). Kısa ve açıklayıcı ol.',
    aciklama: 'Git diff alıp commit mesajı yazar',
  },
  review: {
    prompt: 'Kodu baştan sona review et. Şunlara bak: güvenlik açıkları, performans sorunları, kod kalitesi, test kapsamı. Bulduğun her sorun için öneri yaz.',
    aciklama: 'Kod review yapar',
  },
  test: {
    prompt: 'Bu kod için kapsamlı birim testleri yaz. Jest veya vitest formatında. Edge case\'leri de kapsa.',
    aciklama: 'Birim testleri yazar',
  },
  dokuman: {
    prompt: 'Bu kod için README dokümantasyonu yaz. Ne işe yaradığı, nasıl kurulduğu, API referansı ve örnekler olsun.',
    aciklama: 'Dokümantasyon üretir',
  },
};

function ensureFile(): void {
  const dir = join(homedir(), '.fetih');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  if (!existsSync(TEMPLATES_FILE)) {
    writeFileSync(TEMPLATES_FILE, JSON.stringify(DEFAULT_TEMPLATES, null, 2), 'utf-8');
  }
}

function loadTemplates(): Record<string, TemplateEntry> {
  ensureFile();
  try { return JSON.parse(readFileSync(TEMPLATES_FILE, 'utf-8')); }
  catch { return { ...DEFAULT_TEMPLATES }; }
}

export function getTemplate(name: string): TemplateEntry | null {
  const templates = loadTemplates();
  return templates[name.toLowerCase()] || null;
}

export function listTemplates(): Array<{ name: string } & TemplateEntry> {
  const templates = loadTemplates();
  return Object.entries(templates).map(([name, entry]) => ({ name, ...entry }));
}

export function setTemplate(name: string, prompt: string, aciklama: string): void {
  const templates = loadTemplates();
  templates[name.toLowerCase()] = { prompt, aciklama };
  writeFileSync(TEMPLATES_FILE, JSON.stringify(templates, null, 2), 'utf-8');
}

export function deleteTemplate(name: string): boolean {
  const templates = loadTemplates();
  const key = name.toLowerCase();
  if (!templates[key]) return false;
  delete templates[key];
  writeFileSync(TEMPLATES_FILE, JSON.stringify(templates, null, 2), 'utf-8');
  return true;
}

export function applyTemplate(name: string, context?: string): string {
  const template = getTemplate(name);
  if (!template) return '';
  return context ? `${template.prompt}\n\nBağlam: ${context}` : template.prompt;
}

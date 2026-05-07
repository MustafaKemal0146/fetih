/**
 * @fileoverview Otomatik bellek çıkarma — konuşma sonunda AI önemli bilgileri kaydeder.
 */

import { join } from 'path';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from 'fs';
import { homedir } from 'os';
import type { ChatMessage, LLMProvider, ChatOptions } from './types.js';

const MEMORY_DIR = join(homedir(), '.fetih', 'auto-memory');
const MIN_MESSAGES_FOR_EXTRACT = 4; // En az bu kadar mesaj olsun

/**
 * Konuşmadan önemli bilgileri çıkar ve kaydet.
 */
export async function extractAndSaveMemories(
  messages: ChatMessage[],
  provider: LLMProvider,
  model: string,
  cwd: string,
): Promise<void> {
  if (messages.length < MIN_MESSAGES_FOR_EXTRACT) return;

  try {
    const transcript = messages
      .filter(m => m.role !== 'system')
      .slice(-20) // Son 20 mesaj
      .map(m => `${m.role === 'user' ? 'Kullanıcı' : 'FETİH'}: ${typeof m.content === 'string' ? m.content : JSON.stringify(m.content)}`)
      .join('\n\n');

    const extractPrompt = `Aşağıdaki konuşmadan gelecekte hatırlanması gereken önemli bilgileri çıkar.
Sadece gerçekten önemli olanları yaz: tercihler, kararlar, proje detayları, teknik seçimler.
Kısa ve öz tut. Eğer hatırlanacak önemli bir şey yoksa sadece "YOK" yaz.

Konuşma:
${transcript}

Hatırlanacak bilgiler (madde madde):`;

    const options: ChatOptions = {
      model,
      maxTokens: 500,
      temperature: 0.1,
    };

    let memoryText = '';
    for await (const event of provider.stream([{ role: 'user', content: extractPrompt }], options)) {
      if (event.type === 'text') memoryText += event.data as string;
      if (event.type === 'done') break;
    }

    memoryText = memoryText.trim();
    if (!memoryText || memoryText === 'YOK' || memoryText.toLowerCase().includes('yok')) return;

    // Kaydet
    if (!existsSync(MEMORY_DIR)) mkdirSync(MEMORY_DIR, { recursive: true });
    
    const date = new Date().toISOString().split('T')[0];
    const memFile = join(MEMORY_DIR, `${date}.md`);
    
    let existing = '';
    if (existsSync(memFile)) existing = readFileSync(memFile, 'utf-8');
    
    const entry = `\n## ${new Date().toLocaleTimeString('tr-TR')} — ${cwd}\n\n${memoryText}\n`;
    writeFileSync(memFile, existing + entry, 'utf-8');

    // v3.8.17: Bellek sıkıştırma — eğer dosya çok büyüdüyse özetle
    if (existing.length > 20000) {
      await compressAutoMemory(memFile, provider, model);
    }
  } catch { /* sessizce geç */ }
}

/**
 * Eski bellek girişlerini özetleyerek sıkıştırır (v3.8.17).
 */
async function compressAutoMemory(filePath: string, provider: LLMProvider, model: string): Promise<void> {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const compressPrompt = `Aşağıdaki geçmiş bellek kayıtlarını oku ve tek bir maddeleştirilmiş özet haline getir. 
Tekrarları temizle, sadece hala geçerli olan önemli bilgileri koru.

Kayıtlar:
${content}

Özetlenmiş Bellek:`;

    let summary = '';
    for await (const event of provider.stream([{ role: 'user', content: compressPrompt }], { model, maxTokens: 1000 })) {
      if (event.type === 'text') summary += event.data as string;
      if (event.type === 'done') break;
    }

    if (summary.trim()) {
      writeFileSync(filePath, `# SIKIŞTIRILMIŞ BELLEK (${new Date().toLocaleDateString('tr-TR')})\n\n${summary.trim()}\n`, 'utf-8');
    }
  } catch { /* ignore */ }
}

/**
 * Proje bazlı otomatik bellek oluşturma (v3.8.17).
 */
export async function ensureProjectMetadata(cwd: string, provider: LLMProvider, model: string): Promise<void> {
  const fetihDir = join(cwd, '.fetih');
  const projectMd = join(fetihDir, 'project.md');

  if (existsSync(projectMd)) return;

  try {
    if (!existsSync(fetihDir)) mkdirSync(fetihDir, { recursive: true });

    const analyzePrompt = `Mevcut dizindeki dosyaları incele ve projenin ne olduğunu, hangi teknolojileri kullandığını, 
yapısını ve amacını özetleyen bir 'project.md' içeriği hazırla.
Kısa, teknik ve öz olsun.

Dizin: ${cwd}`;

    let summary = '';
    for await (const event of provider.stream([{ role: 'user', content: analyzePrompt }], { model, maxTokens: 800 })) {
      if (event.type === 'text') summary += event.data as string;
      if (event.type === 'done') break;
    }

    if (summary.trim()) {
      writeFileSync(projectMd, summary.trim(), 'utf-8');
    }
  } catch { /* ignore */ }
}

/**
 * Otomatik belleği oku.
 */
export function loadAutoMemories(limit = 5): string {
  if (!existsSync(MEMORY_DIR)) return '';
  try {
    const files = readdirSync(MEMORY_DIR)
      .filter((f: string) => f.endsWith('.md'))
      .sort()
      .reverse()
      .slice(0, limit);
    return files.map((f: string) => readFileSync(join(MEMORY_DIR, f), 'utf-8')).join('\n');
  } catch { return ''; }
}

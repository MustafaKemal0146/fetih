/**
 * @fileoverview Skills sistemi — .seth/skills/ dizininden özel komutlar yükler.
 * gemini-cli'nin skillLoader.ts'inden ilham alınmıştır.
 *
 * Skill formatı (markdown frontmatter):
 * ---
 * name: skill-adi
 * description: Ne yapar
 * ---
 * Skill içeriği buraya...
 */

import { existsSync, readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

export interface SkillDefinition {
  name: string;
  description: string;
  body: string;
  location: string;
}

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n([\s\S]*))?/;

function parseFrontmatter(content: string): { name: string; description: string } | null {
  const match = content.match(FRONTMATTER_RE);
  if (!match) return null;
  const fm = match[1] ?? '';
  const nameMatch = fm.match(/^name:\s*(.+)$/m);
  const descMatch = fm.match(/^description:\s*(.+)$/m);
  if (!nameMatch || !descMatch) return null;
  return { name: nameMatch[1]!.trim(), description: descMatch[1]!.trim() };
}

/**
 * Skills dizinlerinden skill'leri yükle.
 * Sıra: ~/.seth/skills/ → ./.seth/skills/
 */
export function loadSkills(cwd: string): SkillDefinition[] {
  const dirs = [
    join(homedir(), '.seth', 'skills'),
    join(cwd, '.seth', 'skills'),
  ];

  const skills: SkillDefinition[] = [];
  const seen = new Set<string>();

  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    try {
      const files = readdirSync(dir).filter(f => f.endsWith('.md') || f.endsWith('.txt'));
      for (const file of files) {
        const filePath = join(dir, file);
        const content = readFileSync(filePath, 'utf-8');
        const fm = parseFrontmatter(content);
        if (!fm) continue;
        if (seen.has(fm.name)) continue; // cwd override
        seen.add(fm.name);
        const bodyMatch = content.match(FRONTMATTER_RE);
        const body = bodyMatch?.[2]?.trim() ?? content.trim();
        skills.push({ name: fm.name, description: fm.description, body, location: filePath });
      }
    } catch { /* ignore */ }
  }

  return skills;
}

/**
 * Skill'i sistem promptuna eklenecek formata çevir.
 */
export function formatSkillsForPrompt(skills: SkillDefinition[]): string {
  if (skills.length === 0) return '';
  const lines = ['', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'YÜKLÜ SKİLL\'LER', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'];
  for (const s of skills) {
    lines.push(`\n## ${s.name}\n${s.description}\n\n${s.body}`);
  }
  return lines.join('\n');
}

// ─── v3.9.2: /skills ve /skill komutları için ──────────────────────���─────────

import { fileURLToPath } from 'url';
import { dirname as pathDirname } from 'path';
import { mkdirSync } from 'fs';

const _skillsFilename = fileURLToPath(import.meta.url);
const _skillsDir = pathDirname(_skillsFilename);

/** Built-in skill dizini: dist/skills/ (derleme sonrası) */
const BUILTIN_SKILLS_DIR = join(_skillsDir, 'skills');

/** Tüm skill'leri (built-in + kullanıcı) listele */
export function listAllSkills(): SkillDefinition[] {
  const skills: SkillDefinition[] = [];
  const seen = new Set<string>();

  // Built-in skills (dist/skills/)
  if (existsSync(BUILTIN_SKILLS_DIR)) {
    try {
      const files = readdirSync(BUILTIN_SKILLS_DIR).filter(f => f.endsWith('.md')).sort();
      for (const file of files) {
        const filePath = join(BUILTIN_SKILLS_DIR, file);
        const content = readFileSync(filePath, 'utf-8');
        const fm = parseFrontmatter(content);
        if (!fm) continue;
        seen.add(fm.name);
        const bodyMatch = content.match(FRONTMATTER_RE);
        const body = bodyMatch?.[2]?.trim() ?? content.trim();
        skills.push({ name: fm.name, description: fm.description, body, location: filePath });
      }
    } catch { /* ignore */ }
  }

  // Kullanıcı skill'leri: ~/.seth/skills/
  const userDir = join(homedir(), '.seth', 'skills');
  if (!existsSync(userDir)) {
    try { mkdirSync(userDir, { recursive: true }); } catch { /* ignore */ }
  }
  if (existsSync(userDir)) {
    try {
      const files = readdirSync(userDir).filter(f => f.endsWith('.md')).sort();
      for (const file of files) {
        const filePath = join(userDir, file);
        const content = readFileSync(filePath, 'utf-8');
        const fm = parseFrontmatter(content);
        if (!fm) continue;
        const bodyMatch = content.match(FRONTMATTER_RE);
        const body = bodyMatch?.[2]?.trim() ?? content.trim();
        const idx = skills.findIndex(s => s.name === fm.name);
        if (idx >= 0) {
          skills[idx] = { name: fm.name, description: fm.description, body, location: filePath };
        } else {
          skills.push({ name: fm.name, description: fm.description, body, location: filePath });
          seen.add(fm.name);
        }
      }
    } catch { /* ignore */ }
  }

  return skills;
}

/** Belirtilen skill'i bul ve döndür */
export function findSkill(name: string): SkillDefinition | null {
  return listAllSkills().find(s => s.name.toLowerCase() === name.toLowerCase()) ?? null;
}

/** Skill prompt'undaki {{params}} yer tutucularını doldur */
export function renderSkill(skill: SkillDefinition, params: string): string {
  if (!params.trim()) return skill.body;
  return skill.body.replace(/\{\{params?\}\}/gi, params.trim());
}

/** Skill listesini tablo olarak formatla */
export function formatSkillsTable(skills: SkillDefinition[]): string {
  if (skills.length === 0) {
    return [
      '  Skill bulunamadı.',
      '  Kendi skill\'lerinizi eklemek için: ~/.seth/skills/<ad>.md',
    ].join('\n');
  }
  const lines: string[] = ['  Skill\'ler\n  ' + '─'.repeat(40)];
  const builtin = skills.filter(s => s.location.includes(BUILTIN_SKILLS_DIR));
  const user = skills.filter(s => !s.location.includes(BUILTIN_SKILLS_DIR));

  if (builtin.length > 0) {
    lines.push('\x1b[90m  Built-in:\x1b[0m');
    for (const s of builtin) {
      lines.push(`    \x1b[36m/skill ${s.name}\x1b[0m${' '.repeat(Math.max(1, 22 - s.name.length))}${s.description}`);
    }
  }
  if (user.length > 0) {
    lines.push('\x1b[90m  Kullanıcı tanımlı:\x1b[0m');
    for (const s of user) {
      lines.push(`    \x1b[36m/skill ${s.name}\x1b[0m${' '.repeat(Math.max(1, 22 - s.name.length))}${s.description}`);
    }
  }
  lines.push(`\n  Yeni skill: ~/.seth/skills/<ad>.md`);
  return lines.join('\n');
}

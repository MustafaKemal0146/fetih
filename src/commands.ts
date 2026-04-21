/**
 * @fileoverview Slash command handlers.
 */

import chalk from 'chalk';
import { cmd, promptBright } from './theme.js';
import { select, isCancel, confirm, text } from '@clack/prompts';
import { writeFile } from 'fs/promises';
import { resolve, join } from 'path';
import { homedir } from 'os';
import type { ProviderName, SETHConfig, ChatMessage, PermissionLevel, ThinkingStyle } from './types.js';
import { VERSION } from './version.js';
import { todoListesiniOku } from './session-runtime.js';
import { runRepoOzetSummary } from './tools/repo-ozet.js';
import { runSorWizard } from './sor-wizard.js';
import { runNasilCalisirAnimation } from './nasilcalisir.js';
import { sethEngine } from './tools/seth-engine.js';
import { readMemory, writeMemory, appendMemory, loadAllMemories, type MemoryType } from './storage/memory.js';
import { loadHooks, getHooksExample } from './hooks.js';
import { loadHistory } from './storage/history.js';
import { exportSecurityReport } from './security-report.js';
import { 
  resolveModel, 
  loadConfig, 
  saveConfig, 
  persistProviderAndModel, 
  getEffectiveContextBudgetTokens,
  deleteApiKey,
} from './config/settings.js';
import { listSessions, setSessionTag } from './storage/session.js';
import { THEMES, type ThemeName, setTheme, getThemeColors } from './theme.js';

export interface CommandContext {
  config: SETHConfig;
  currentProvider: ProviderName;
  currentModel: string;
  toolsEnabled: boolean;
  agentEnabled: boolean;
  setProvider: (name: ProviderName) => Promise<void>;
  setModel: (model: string) => void;
  setToolsEnabled: (enabled: boolean) => void;
  setAgentEnabled: (enabled: boolean) => void;
  clearHistory: (scope?: 'active' | 'all') => void;
  getContextBudgetTokens: () => number;
  setContextBudgetTokens: (n: number) => void;
  getActiveLane: () => 'a' | 'b';
  setActiveLane: (lane: 'a' | 'b') => void;
  compactHistory: () => Promise<{ before: number; after: number } | null>;
  undoHistory: () => boolean;
  changeCwd: (dir: string) => string | null;
  getCwd: () => string;
  getHistory: () => ChatMessage[];
  getPermissionLevel: () => PermissionLevel;
  setPermissionLevel: (level: PermissionLevel) => void;
  getStats: () => { messages: number; inputTokens: number; outputTokens: number; turns: number };
  getSessionId: () => string;
  setThinkingStyle: (style: ThinkingStyle) => void;
  setVimMode: (enabled: boolean) => void;
  getMessages?: () => ChatMessage[];
}

export interface CommandResult {
  output?: string;
  shouldExit?: boolean;
  clearAndAnimate?: boolean;
  runAsUserMessage?: string;
}

const PERM_LABELS: Record<PermissionLevel, string> = {
  full: 'Tam — hiçbir şey sormaz',
  normal: 'Normal — yazma/çalıştırma işlemleri onay ister',
  dar: 'Dar — her araç onay ister',
};

// ─── Checkbox seçici (raw mode, boşluk=seç, Enter=onayla) ───────────────────
export const COMMANDS: Record<string, (args: string, ctx: CommandContext) => Promise<CommandResult> | CommandResult> = {
  yardım: (_args, ctx) => ({
    output: [
      chalk.bold(`SETH v${VERSION} — Komut Rehberi`),
      '',
      chalk.dim('  ─── Bilgi & Analiz ───────────────────────────────────────────'),
      `  ${cmd('/özellikler')}                    SETH yetenek raporunu göster`,
      `  ${cmd('/harita')}                        Canlı operasyon haritası (SETH Engine)`,
      `  ${cmd('/istatistikler')}                 Token kullanımı, maliyet tahmini, günlük kullanım`,
      `  ${cmd('/kullanım')}                      Bugünkü kullanım limitinizi göster`,
      `  ${cmd('/bağlam')}                        Token dağılımı, araç kullanım analizi`,
      `  ${cmd('/ara')} ${chalk.dim('<kelime>')}                  Mevcut konuşmada ara`,
      `  ${cmd('/doktor')}                        Ortam sağlığı + araç kontrolü + otomatik kurulum`,
      `  ${cmd('/repo_özet')}                     Git: dal, son commit, diff --stat, status`,
      `  ${cmd('/güncelle')}                      Yeni sürüm kontrolü (semver)`,
      '',
      chalk.dim('  ─── Bellek & Oturum ──────────────────────────────────────────'),
      `  ${cmd('/hafıza')}                        Kalıcı belleği göster (user/project/feedback/reference)`,
      `  ${cmd('/hafıza')} ${chalk.dim('ekle <tip> <içerik>')}    Belleğe yeni giriş ekle`,
      `  ${cmd('/hafıza')} ${chalk.dim('sil <tip>')}              Belirli bellek tipini temizle`,
      `  ${cmd('/hafıza-temizle')}                Tüm kalıcı belleği sil (onay ister)`,
      `  ${cmd('/bellek')}                        Görev listesi + oturum özeti`,
      `  ${cmd('/context-temizle')}               Oturumu sıfırla, yeni konuşma başlat`,
      `  ${cmd('/temizle')}                       Konuşma geçmişini temizle`,
      `  ${cmd('/sıkıştır')}                      Geçmişi AI ile özetle ve sıkıştır`,
      `  ${cmd('/geri')}                          Son mesajı geri al`,
      `  ${cmd('/kaydet')} ${chalk.dim('[md|html|txt] [dosya]')}  Konuşmayı dışa aktar`,
      `  ${cmd('/geçmiş')}                        Önceki oturumu devam ettir`,
      `  ${cmd('/etiket')} ${chalk.dim('<isim>')}                 Oturumu adlandır / etiketle`,
      '',
      chalk.dim('  ─── Ayarlar ──────────────────────────────────────────────────'),
      `  ${cmd('/değiştir')}                      Etkileşimli ayar menüsü`,
      `  ${cmd('/sağlayıcı')} ${chalk.dim('<isim>')}             Sağlayıcı: claude, gemini, openai, ollama, groq, deepseek, mistral, xai, lmstudio, openrouter`,
      `  ${cmd('/model')} ${chalk.dim('<isim>')}                 Model adını doğrudan ayarla`,
      `  ${cmd('/profil')}                        Kayıtlı sağlayıcı+model profilleri`,
      `  ${cmd('/modeller')}                      Mevcut modelleri listele ve seç`,
      `  ${cmd('/araçlar')} ${chalk.dim('<açık|kapalı>')}        Araç kullanımını aç/kapat`,
      `  ${cmd('/ajan')} ${chalk.dim('<açık|kapalı>')}           Çok tur ajan modunu aç/kapat`,
      `  ${cmd('/yetki')} ${chalk.dim('<full|normal|dar>')}      İzin seviyesini ayarla`,
      `  ${cmd('/tema')}                          Renk teması (dark, light, cyberpunk, retro, ocean, sunset)`,
      `  ${cmd('/apikey')}                        API anahtarlarını yönet / sil`,
      `  ${cmd('/context')} ${chalk.dim('<miktar>')}             Token bütçesi (örn: 500k, 2M)`,
      '',
      chalk.dim('  ─── Araçlar & Sistem ─────────────────────────────────────────'),
      `  ${cmd('/hook')} ${chalk.dim('[liste|örnek]')}           Hook sistemi (PreToolUse/PostToolUse)`,
      `  ${cmd('/rapor')} ${chalk.dim('pdf')}                    Güvenlik taramasını LaTeX/PDF olarak aktar`,
      `  ${cmd('/görevler')}                      Arka plan görevlerini listele`,
      `  ${cmd('/yan-sorgu')} ${chalk.dim('<soru>')}             Konuşmayı bozmadan hızlı soru sor`,
      `  ${cmd('/sor')}                           İstek sihirbazını başlat`,
      `  ${cmd('/dusunme')}                       Düşünme göstergesini aç/kapat`,
      `  ${cmd('/cd')} ${chalk.dim('<dizin>')}                   Çalışma dizinini değiştir`,
      `  ${cmd('/pwd')}                           Mevcut dizini göster`,
      `  ${cmd('/nasılçalışır')}                  Canlı demo (typewriter animasyonu)`,
      `  ${cmd('/cikis')}                         Uygulamadan çık`,
      '',
      chalk.dim('  ─── Kısayollar ───────────────────────────────────────────────'),
      chalk.dim('  Ctrl+C   İşlemi iptal et'),
      chalk.dim('  Ctrl+D   Çıkış'),
      chalk.dim('  Ctrl+R   Geçmiş fuzzy arama'),
      chalk.dim('  Esc      AI yanıtını durdur'),
      chalk.dim('  ↑↓       Geçmiş komutlar'),
      chalk.dim('  \\        Satır sonu — çok satırlı girdi'),
      '',
      chalk.dim(`  İzin: ${ctx.getPermissionLevel()}  •  Sağlayıcı: ${ctx.currentProvider}  •  Model: ${ctx.currentModel}`),
    ].join('\n'),
  }),
  özellikler: async () => ({
    output: `
🎯 SETH v${VERSION} 'LEVIATHAN' — Yetenek Raporu (v3.8.17)

1. Siber Harekat (Multi-Target Campaign)
   • IP aralıkları (CIDR) ve wildcard alan adları (*.site.com) üzerinde otonom harekat.
   • Ağdaki en zayıf halkayı (IoT, Printer, Legacy Server) otomatik tespit etme.

2. OSINT ve Sızıntı Verisi (Breach-Feeder)
   • breach_query: Hedef domain ile ilişkili sızdırılmış e-posta/şifre verilerini otonom çekme.
   • OSINT tabanlı akıllı brute-force saldırıları.
   • Shodan: Gerçek zamanlı ağ keşfi ve zafiyet tespiti.

3. Operasyon Haritası (Live Attack Map)
   • /harita: Operasyonun hangi aşamada olduğunu ve keşfedilen varlıkları görselleştirme.

4. Gelişmiş İstismar ve Denetim
   • bypass_cloudflare: Gerçek IP tespiti.
   • brute_force & exploit_search: Otonom sızma ve derinlemesine istismar (John/Hashcat).

SETH artık bir ordu gibi düşünen 'Leviathan' çekirdeğine sahip. Yaratıcısı: Mustafa Kemal Çıngıl 😈🐍🔥
`,
  }),

  harita: async () => {
    const res = await sethEngine({ target: 'STATE', action: 'get_map' });
    if (res.isError) return { output: chalk.red('Harita verisi alınamadı.') };
    
    const state = JSON.parse(res.output).data;
    let output = `\n${chalk.bold.cyan('🌐 SETH CANLI OPERASYON HARİTASI')}\n`;
    output += `${chalk.dim('Başlangıç:')} ${state.start_time}\n`;
    output += `─`.repeat(40) + '\n';

    for (const [target, info] of Object.entries(state.targets)) {
      const targetInfo = info as any;
      output += `${chalk.green('●')} ${chalk.bold(target)}\n`;
      if (targetInfo.subdomains.length) output += `  ├─ ${chalk.blue('Subdomainler:')} ${targetInfo.subdomains.length} adet\n`;
      if (targetInfo.ports.length) {
        output += `  ├─ ${chalk.yellow('Açık Portlar:')}\n`;
        targetInfo.ports.forEach((p: string) => output += `  │  └── ${p}\n`);
      }
      output += `  └─ ${chalk.magenta('Riskler:')} ${targetInfo.risks.length || 'Analiz Ediliyor'}\n`;
    }

    if (state.leaks.length) {
      output += `\n${chalk.red('🔥 SIZINTI VERİLERİ (BREACHES)')}\n`;
      state.leaks.forEach((l: any) => output += `  • ${l.user} [${l.source}]\n`);
    }

    return { output: output + '\n' };
  },

  yetki: async (args, ctx) => {
    const level = args.trim().toLowerCase();
    const valid: PermissionLevel[] = ['full', 'normal', 'dar'];
    if (!level) {
      const p = await select({
        message: 'İzin seviyesini seçin:',
        options: [
          { value: 'full',   label: 'Tam (onay istemez)' },
          { value: 'normal', label: 'Normal (yazma/çalıştırma onay ister)' },
          { value: 'dar',    label: 'Dar (her araç onay ister)' },
        ],
      });
      if (isCancel(p)) return { output: chalk.dim('İptal edildi.') };
      ctx.setPermissionLevel(p as PermissionLevel);
      saveConfig({ tools: { ...ctx.config.tools, requireConfirmation: p !== 'full' } });
      return { output: chalk.green(`✓ İzin seviyesi: ${p}`) };
    }
    if (!valid.includes(level as any)) return { output: chalk.red('Geçersiz seviye: full, normal, dar') };
    ctx.setPermissionLevel(level as PermissionLevel);
    saveConfig({ tools: { ...ctx.config.tools, requireConfirmation: level !== 'full' } });
    return { output: chalk.green(`✓ İzin seviyesi: ${level}`) };
  },

  sağlayıcı: async (args, ctx) => {
    const name = args.trim().toLowerCase() as ProviderName;
    if (!name) {
      const p = await select({
        message: 'Sağlayıcı seçin:',
        options: [
          { value: 'claude',    label: 'Claude (Anthropic)' },
          { value: 'gemini',    label: 'Gemini (Google)' },
          { value: 'openai',    label: 'OpenAI' },
          { value: 'ollama',    label: 'Ollama (Yerel)' },
          { value: 'groq',      label: 'Groq' },
          { value: 'deepseek',  label: 'DeepSeek' },
          { value: 'mistral',   label: 'Mistral' },
          { value: 'xai',       label: 'xAI (Grok)' },
          { value: 'lmstudio',  label: 'LM Studio' },
          { value: 'openrouter',label: 'OpenRouter' },
        ],
      });
      if (isCancel(p)) return { output: chalk.dim('İptal edildi.') };
      await ctx.setProvider(p as ProviderName);
      persistProviderAndModel(p as ProviderName, ctx.currentModel);
      return { output: chalk.green(`✓ Sağlayıcı değiştirildi: ${p}`) };
    }
    await ctx.setProvider(name);
    persistProviderAndModel(name, ctx.currentModel);
    return { output: chalk.green(`✓ Sağlayıcı değiştirildi: ${name}`) };
  },

  model: (args, ctx) => {
    const model = args.trim();
    if (!model) return { output: chalk.dim(`Mevcut model: ${ctx.currentModel}`) };
    ctx.setModel(model);
    persistProviderAndModel(ctx.currentProvider, model);
    return { output: chalk.green(`✓ Model ayarlandı: ${model}`) };
  },

  modeller: async (_args, ctx) => {
    try {
      const { listModels } = await import('./providers/factory.js');
      const models = await listModels(ctx.currentProvider, ctx.config.providers[ctx.currentProvider]);
      if (models.length === 0) return { output: chalk.yellow('Model listesi alınamadı veya boş.') };
      const selected = await select({
        message: `${ctx.currentProvider} için model seçin:`,
        options: models.map((m: string) => ({ value: m, label: m })),
      });
      if (isCancel(selected)) return { output: chalk.dim('İptal edildi.') };
      ctx.setModel(selected as string);
      persistProviderAndModel(ctx.currentProvider, selected as string);
      return { output: chalk.green(`✓ Model seçildi: ${selected}`) };
    } catch (err) {
      return { output: chalk.red(`Hata: ${err instanceof Error ? err.message : String(err)}`) };
    }
  },

  değiştir: async (_args, ctx) => {
    const action = await select({
      message: 'Ayar seçin:',
      options: [
        { value: 'provider', label: 'Sağlayıcı (Provider)' },
        { value: 'model',    label: 'Model' },
        { value: 'perm',     label: 'İzin Seviyesi' },
        { value: 'theme',    label: 'Tema' },
        { value: 'tools',    label: 'Araçlar (Aç/Kapat)' },
      ],
    });
    if (isCancel(action)) return { output: chalk.gray('İptal edildi.') };

    switch (action) {
      case 'provider': return COMMANDS.sağlayıcı('', ctx);
      case 'model':    return COMMANDS.modeller('', ctx);
      case 'perm':     return COMMANDS.yetki('', ctx);
      case 'theme':    return COMMANDS.tema('', ctx);
      case 'tools': {
        const toggle = ctx.toolsEnabled ? 'Kapat' : 'Aç';
        const ok = await confirm({ message: `Araç kullanımı ${toggle.toLowerCase()}ılsın mı?` });
        if (ok) {
          ctx.setToolsEnabled(!ctx.toolsEnabled);
          return { output: chalk.green(`✓ Araçlar: ${!ctx.toolsEnabled ? 'Kapalı' : 'Açık'}`) };
        }
        return { output: chalk.gray('Değişiklik yapılmadı.') };
      }
    }
    return { output: '' };
  },

  temizle: (_args, ctx) => {
    ctx.clearHistory('active');
    return { output: chalk.green('✓ Konuşma geçmişi temizlendi.') };
  },

  'context-temizle': async (_args, ctx) => {
    const sure = await confirm({ message: 'Tüm oturum sıfırlansın mı? (Yeni konuşma)' });
    if (isCancel(sure) || !sure) return { output: chalk.gray('İptal edildi.') };
    ctx.clearHistory('all');
    return { output: chalk.green('✓ Oturum sıfırlandı. Yeni bir başlangıç!') };
  },

  geri: (_args, ctx) => {
    const ok = ctx.undoHistory();
    return { output: ok ? chalk.green('✓ Son mesaj geri alındı.') : chalk.yellow('Geri alınacak mesaj yok.') };
  },

  sıkıştır: async (_args, ctx) => {
    const res = await ctx.compactHistory();
    if (!res) return { output: chalk.yellow('Geçmiş henüz sıkıştırmak için yeterince uzun değil.') };
    return { output: chalk.green(`✓ Sıkıştırıldı: ${res.before} -> ${res.after} mesaj.`) };
  },

  kaydet: async (args, ctx) => {
    const parts = args.trim().split(' ');
    const fmt = ['md', 'html', 'txt', 'cast'].includes(parts[0] ?? '') ? parts.shift()! : 'md';
    const filename = parts.join(' ') || `seth_chat_${Date.now()}.${fmt}`;
    const messages = ctx.getHistory();

    let content = '';
    if (fmt === 'html') {
      const rows = messages.map(m => {
        const role = m.role === 'user' ? 'Sen' : 'SETH';
        const cls = m.role === 'user' ? 'user' : 'assistant';
        const text = typeof m.content === 'string' ? m.content : JSON.stringify(m.content);
        return `<div class="msg ${cls}"><span class="role">${role}</span><pre>${text}</pre></div>`;
      }).join('\n');
      
      content = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SETH Chat</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d0d0d;color:#e0e0e0;font-family:'Courier New',monospace;max-width:900px;margin:0 auto;padding:24px}
  h1{color:#cc0000;font-size:1.4rem;margin-bottom:20px;border-bottom:1px solid #333;padding-bottom:10px}
  .msg{padding:14px 18px;margin:10px 0;border-radius:8px;border-left:3px solid transparent}
  .user{background:#1e1e1e;border-color:#555}
  .assistant{background:#0f1a2e;border-color:#cc0000}
  .role{font-size:.75rem;font-weight:bold;text-transform:uppercase;letter-spacing:.1em;opacity:.6;display:block;margin-bottom:6px}
  .user .role{color:#aaa}
  .assistant .role{color:#cc4444}
  pre{white-space:pre-wrap;word-break:break-word;font-size:.9rem;line-height:1.6}
</style>
</head>
<body>
<h1>🐍 SETH — Sohbet Kaydı</h1>
${rows}
</body></html>`;
    } else if (fmt === 'txt') {
      content = messages.map(m => `[${m.role.toUpperCase()}]\n${typeof m.content === 'string' ? m.content : JSON.stringify(m.content)}\n`).join('\n---\n\n');
    } else if (fmt === 'cast') {
      const { exportAsAsciicast } = await import('./asciicast.js');
      content = exportAsAsciicast(messages, ctx.currentProvider, ctx.currentModel);
    } else {
      content = messages.map(m => `### ${m.role.toUpperCase()}\n\n${typeof m.content === 'string' ? m.content : JSON.stringify(m.content)}`).join('\n\n---\n\n');
    }

    await writeFile(resolve(ctx.getCwd(), filename), content);
    return { output: chalk.green(`✓ Kaydedildi: ${filename} (${fmt.toUpperCase()})`) };
  },

  // #18 /export — oturum export/import
  export: async (args, ctx) => {
    const parts = args.trim().split(' ');
    const fmt = ['json', 'md', 'html', 'obsidian'].includes(parts[0] ?? '') ? parts.shift()! : 'json';
    const filename = parts.join(' ') || `seth_export_${Date.now()}.${fmt === 'obsidian' ? 'md' : fmt}`;
    const messages = ctx.getHistory();
    const stats = ctx.getStats();

    let content: string;
    if (fmt === 'json') {
      content = JSON.stringify({
        version: VERSION,
        provider: ctx.currentProvider,
        model: ctx.currentModel,
        exportedAt: new Date().toISOString(),
        stats,
        messages: messages.map(m => ({
          role: m.role,
          content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content),
        })),
      }, null, 2);
    } else if (fmt === 'obsidian') {
      const fm = `---\ntitle: SETH Oturum Kaydı\ntags: [seth, ai-session, security]\nprovider: ${ctx.currentProvider}\nmodel: ${ctx.currentModel}\ndate: ${new Date().toISOString()}\n---\n\n`;
      content = fm + messages.map(m => {
        const role = m.role === 'user' ? '# User' : '# SETH';
        const text = typeof m.content === 'string' ? m.content : JSON.stringify(m.content, null, 2);
        return `${role}\n\n${text}`;
      }).join('\n\n---\n\n');
    } else if (fmt === 'md') {
      const header = `# SETH Oturum Kaydı\n\n**Provider:** ${ctx.currentProvider} / ${ctx.currentModel}  \n**Tarih:** ${new Date().toLocaleString('tr-TR')}  \n**Mesaj:** ${stats.messages}  \n\n---\n\n`;
      content = header + messages.map(m => {
        const role = m.role === 'user' ? '**Sen**' : '**SETH**';
        const text = typeof m.content === 'string' ? m.content : JSON.stringify(m.content, null, 2);
        return `${role}\n\n${text}`;
      }).join('\n\n---\n\n');
    } else {
      // HTML
      const rows = messages.map(m => {
        const role = m.role === 'user' ? 'Sen' : 'SETH';
        const cls = m.role === 'user' ? 'user' : 'assistant';
        const text = typeof m.content === 'string' ? m.content : JSON.stringify(m.content);
        return `<div class="msg ${cls}"><span class="role">${role}</span><pre>${text}</pre></div>`;
      }).join('\n');
      content = `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{background:#0d0d0d;color:#eee;font-family:monospace;padding:20px}.msg{margin:10px 0;padding:10px;border-radius:5px}.user{background:#222}.assistant{background:#111;border-left:3px solid #cc0000}.role{font-weight:bold;display:block;margin-bottom:5px}pre{white-space:pre-wrap}</style></head><body>${rows}</body></html>`;
    }

    await writeFile(resolve(ctx.getCwd(), filename), content);
    return { output: chalk.green(`✓ Oturum ihraç edildi: ${filename}`) };
  },

  hafıza: async (args, ctx) => {
    const parts = args.trim().split(' ');
    const sub = parts[0];
    const tip = parts[1];
    const icerik = parts.slice(2).join(' ');

    if (sub === 'ekle' && tip && icerik) {
      appendMemory(tip as MemoryType, icerik);
      return { output: chalk.green(`✓ Belleğe eklendi (${tip})`) };
    }
    if (sub === 'sil' && tip) {
      writeMemory(tip as MemoryType, '');
      return { output: chalk.green(`✓ Bellek temizlendi (${tip})`) };
    }

    const all = loadAllMemories();
    if (!all) return { output: chalk.gray('Kalıcı bellek boş.') };
    return { output: [chalk.bold('🧠 Kalıcı Bellek'), '', all].join('\n') };
  },

  'hafıza-temizle': async () => {
    const sure = await confirm({ message: 'Tüm kalıcı bellek silinsin mi? (geri alınamaz)' });
    if (isCancel(sure) || !sure) return { output: chalk.dim('İptal edildi.') };
    for (const tip of ['user', 'project', 'feedback', 'reference'] as const) {
      writeMemory(tip, '');
    }
    return { output: chalk.green('✓ Tüm kalıcı bellek temizlendi.') };
  },

  // ─── Konuşma İçi Arama ───────────────────────────────────────────────────
  ara: (_args, ctx) => {
    const query = _args.trim().toLowerCase();
    if (!query) return { output: chalk.dim('Kullanım: /ara <kelime>') };
    const messages = ctx.getMessages?.() ?? [];
    const results: string[] = [];
    messages.forEach((msg, i) => {
      const content = typeof msg.content === 'string' ? msg.content
        : Array.isArray(msg.content) ? msg.content.map((b: any) => b.text ?? '').join(' ')
        : '';
      if (content.toLowerCase().includes(query)) {
        const preview = content.slice(0, 120).replace(/\n/g, ' ');
        const role = msg.role === 'user' ? chalk.cyan('Sen') : chalk.green('SETH');
        results.push(`  ${chalk.dim(`#${i + 1}`)} ${role}: ${preview}…`);
      }
    });
    if (results.length === 0) return { output: chalk.dim(`"${query}" bulunamadı.`) };
    return { output: [chalk.bold(`🔍 "${query}" — ${results.length} sonuç:`), '', ...results].join('\n') };
  },

  // #10 Tüm oturumlarda arama
  'oturum-ara': async (args) => {
    const query = args.trim();
    if (!query) return { output: chalk.dim('Kullanım: /oturum-ara <kelime>') };
    const { searchAllSessions } = await import('./session-search.js');
    const results = await searchAllSessions(query);
    if (results.length === 0) return { output: chalk.dim(`"${query}" hiçbir oturumda bulunamadı.`) };
    const lines = [chalk.bold(`🔍 "${query}" — ${results.length} oturumda bulundu:`), ''];
    for (const r of results.slice(0, 10)) {
      lines.push(`  ${chalk.cyan(r.sessionId.slice(0, 8))} ${chalk.dim(r.createdAt.slice(0, 10))} ${r.provider}/${r.model} — ${r.matchCount} eşleşme`);
      lines.push(`    ${chalk.dim('...' + r.preview.slice(0, 80) + '...')}`);
    }
    return { output: lines.join('\n') };
  },

  // #9 Diff görüntüleme
  diff: async (args, ctx) => {
    const { gitDiffTool } = await import('./tools/git-diff.js');
    const staged = args.includes('--staged') || args.includes('-s');
    const stat = args.includes('--stat');
    return gitDiffTool.execute({ staged, stat_only: stat }, ctx.getCwd());
  },

  // #7 Cron yönetimi
  cron: async (args) => {
    const { addCronJob, listCronJobs, removeCronJob, toggleCronJob, parseIntervalStr } = await import('./cron.js');
    const parts = args.trim().split(' ');
    const sub = parts[0];

    if (!sub || sub === 'liste') {
      const jobs = listCronJobs();
      if (jobs.length === 0) return { output: chalk.dim('  Kayıtlı cron görevi yok. /cron ekle <isim> <interval> <prompt>') };
      const lines = [chalk.bold('⏰ Cron Görevleri:'), ''];
      for (const j of jobs) {
        const status = j.enabled ? chalk.green('✓') : chalk.red('✗');
        const interval = `${j.intervalMs / 60000}dk`;
        lines.push(`  ${status} ${j.id.slice(-6)} ${j.name.padEnd(15)} ${chalk.dim(interval)} — ${j.prompt.slice(0, 50)}`);
      }
      return { output: lines.join('\n') };
    }

    if (sub === 'ekle') {
      const name = parts[1];
      const intervalStr = parts[2];
      const prompt = parts.slice(3).join(' ');
      if (!name || !intervalStr || !prompt) return { output: chalk.red('Kullanım: /cron ekle <isim> <interval(1m/1h/1d)> <prompt>') };
      const ms = parseIntervalStr(intervalStr);
      if (!ms) return { output: chalk.red('Geçersiz interval. Örnek: 30m, 2h, 1d') };
      const job = addCronJob(name, prompt, ms);
      return { output: chalk.green(`✓ Cron görevi eklendi: ${job.id}`) };
    }

    if (sub === 'sil') {
      const id = parts[1];
      if (!id) return { output: chalk.red('Kullanım: /cron sil <id>') };
      const ok = removeCronJob(id);
      return { output: ok ? chalk.green(`✓ Silindi: ${id}`) : chalk.red(`Bulunamadı: ${id}`) };
    }

    return { output: chalk.dim('/cron [liste|ekle|sil]') };
  },

  // #4 Paste — panodan yapıştır
  yapıştır: async (_args, ctx) => {
    const { getClipboardText, hasImageInClipboard, getImageFromClipboard, PASTE_THRESHOLD } = await import('./paste.js');

    // Önce görüntü var mı kontrol et
    if (await hasImageInClipboard()) {
      const img = await getImageFromClipboard();
      if (img) {
        return { 
          output: chalk.green(`🖼️ Panodan görüntü alındı (${Math.round(img.base64.length * 0.75 / 1024)} KB)`),
          runAsUserMessage: `[PASTE_IMAGE]${img.base64}`
        };
      }
    }

    const text = await getClipboardText();
    if (!text) return { output: chalk.yellow('Pano boş.') };
    
    if (text.length > PASTE_THRESHOLD) {
      return {
        output: chalk.cyan(`📋 Büyük metin yapıştırıldı (${text.length} karakter).`),
        runAsUserMessage: text
      };
    }
    return { runAsUserMessage: text };
  },

  hook: async (args) => {
    const sub = args.trim().toLowerCase();
    if (sub === 'örnek') return { output: `Hook örneği (~/.seth/hooks.json):\n\n${JSON.stringify(getHooksExample(), null, 2)}` };
    
    const hooks = loadHooks();
    if (hooks.length === 0) return { output: chalk.gray('Tanımlı hook yok. Örnek için: /hook örnek') };
    const lines = [chalk.bold('🪝 Aktif Hooklar:'), ''];
    hooks.forEach((h, i) => lines.push(`  ${i+1}. ${chalk.cyan(h.event)} ${h.tool ? `[${h.tool}]` : ''} -> ${h.command}`));
    return { output: lines.join('\n') };
  },

  rapor: async (args, ctx) => {
    if (args.trim().toLowerCase() === 'pdf') {
      const history = ctx.getHistory();
      const reportText = history.map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content)).join('\n\n');
      const filename = await exportSecurityReport(reportText, ctx.getCwd());
      return { output: chalk.green(`✓ Güvenlik raporu oluşturuldu: ${filename}`) };
    }
    return { output: chalk.dim('Kullanım: /rapor pdf') };
  },

  cd: (args, ctx) => {
    const newDir = ctx.changeCwd(args.trim());
    return { output: newDir ? chalk.green(`✓ Dizin değiştirildi: ${newDir}`) : chalk.red(`Geçersiz dizin: ${args}`) };
  },

  pwd: (_args, ctx) => ({ output: ctx.getCwd() }),

  nasılçalışır: async () => {
    await runNasilCalisirAnimation();
    return { output: '' };
  },

  istatistikler: async (_args, ctx) => {
    const s = ctx.getStats();
    const history = loadHistory();
    const totalTokens = s.inputTokens + s.outputTokens;

    // #1 Gerçek maliyet hesabı
    const { calculateCostUSD, formatCostUSD } = await import('./model-cost.js');
    const costUSD = calculateCostUSD(s.inputTokens, s.outputTokens, ctx.currentModel, ctx.currentProvider);

    const lines = [
      chalk.bold('📊 SETH İstatistikleri'),
      '',
      `  Sağlayıcı     : ${chalk.cyan(ctx.currentProvider)} / ${chalk.cyan(ctx.currentModel)}`,
      `  Mesaj sayısı  : ${chalk.cyan(s.messages)}`,
      `  Toplam token  : ${chalk.cyan(totalTokens.toLocaleString())}`,
      `    ↳ Giriş     : ${chalk.dim(s.inputTokens.toLocaleString())}`,
      `    ↳ Çıkış     : ${chalk.dim(s.outputTokens.toLocaleString())}`,
      `  Tur sayısı    : ${chalk.cyan(s.turns)}`,
      `  Gerçek maliyet: ${chalk.yellow(formatCostUSD(costUSD))}`,
      '',
      `  Geçmiş kayıt  : ${chalk.cyan(history.length)} komut`,
    ];

    // En çok kullanılan komutlar (v3.8.17)
    const counts: Record<string, number> = {};
    history.forEach(h => {
      const cmd = h.split(' ')[0] || '';
      if (cmd.startsWith('/')) {
        counts[cmd] = (counts[cmd] || 0) + 1;
      }
    });
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    if (top.length > 0) {
      lines.push('', chalk.dim('  Top Komutlar:'));
      top.forEach(([c, n]) => lines.push(`    ${c.padEnd(15)} : ${n} kez`));
    }

    // #17 Tool metrics
    try {
      const { readFile } = await import('fs/promises');
      const { join } = await import('path');
      const { homedir } = await import('os');
      const summaryPath = join(homedir(), '.seth', 'metrics', 'tool-metrics-summary.json');
      const raw = await readFile(summaryPath, 'utf-8').catch(() => null);
      if (raw) {
        const data = JSON.parse(raw);
        lines.push('', chalk.bold('🛠️  Araç Kullanımı (En Çok)'));
        Object.entries(data.usageCount)
          .sort((a: any, b: any) => b[1] - a[1])
          .slice(0, 5)
          .forEach(([name, count]) => {
            lines.push(`  ${name.padEnd(15)} : ${count} kez`);
          });
      }
    } catch { /* ignore */ }

    return { output: lines.join('\n') };
  },

  bellek: async (sub, ctx) => {
    const validTypes: MemoryType[] = ['user', 'project', 'feedback', 'reference'];
    
    // /bellek kaydet <tip> <icerik>
    if (sub.startsWith('kaydet ')) {
      const parts = sub.slice(7).trim().split(' ');
      const tip = parts[0];
      const contentParts = parts.slice(1);
      if (!validTypes.includes(tip as MemoryType)) {
        return { output: chalk.red(`Geçersiz tip. Kullanım: /bellek kaydet <user|project|feedback|reference> <içerik>`) };
      }
      appendMemory(tip as MemoryType, contentParts.join(' '));
      return { output: chalk.green(`✓ Belleğe kaydedildi (${tip})`) };
    }
    // /bellek oku <tip>
    if (sub.startsWith('oku ')) {
      const tip = sub.slice(4).trim() as MemoryType;
      const content = readMemory(tip);
      return { output: content || chalk.dim('(boş)') };
    }
    // /bellek tümü
    if (sub === 'tümü' || sub === 'hepsi') {
      return { output: loadAllMemories() || chalk.dim('(bellek boş)') };
    }
    // Varsayılan: görev listesi + bellek özeti
    const todos = todoListesiniOku(ctx.getSessionId());
    const memSummary = loadAllMemories();
    const lines: string[] = [chalk.bold('📋 Görevler')];
    if (todos.length > 0) lines.push(...todos.map(t => `  [${t.durum}] ${t.baslik}`));
    else lines.push(chalk.dim('  (görev yok)'));
    if (memSummary) {
      lines.push('', chalk.bold('🧠 Bellek'));
      lines.push(memSummary.slice(0, 500));
    }
    lines.push('', chalk.dim('  /bellek kaydet <user|project|feedback|reference> <içerik>'));
    return { output: lines.join('\n') };
  },

  yan: async (args, ctx) => {
    // Yan sorgu (side-query)
    if (!args.trim()) return { output: chalk.dim('Kullanım: /yan <soru>') };
    return { runAsUserMessage: args.trim() };
  },

  effort: async (args, ctx) => {
    const level = args.trim().toLowerCase();
    const levels = ['low', 'medium', 'high', 'max'];
    const desc: Record<string, string> = {
      low: 'Hızlı — kısa yanıtlar, az token',
      medium: 'Dengeli — varsayılan',
      high: 'Derin — uzun, detaylı yanıtlar',
      max: 'Maksimum — en derin düşünme ve analiz',
    };
    if (!level) {
      const selected = await select({
        message: 'Düşünme seviyesini seçin:',
        options: levels.map(l => ({ value: l, label: `${l.padEnd(8)} — ${desc[l]}` })),
      });
      if (isCancel(selected)) return { output: chalk.gray('İptal edildi.') };
      ctx.setThinkingStyle(selected as any);
      saveConfig({ effort: selected as any });
      return { output: chalk.green(`✓ Effort seviyesi: ${selected}`) };
    }
    if (!levels.includes(level)) return { output: chalk.red('Geçersiz seviye: low, medium, high, max') };
    ctx.setThinkingStyle(level as any);
    saveConfig({ effort: level as any });
    return { output: chalk.green(`✓ Effort seviyesi: ${level}`) };
  },

  tema: async (_args, _ctx) => {
    const themeNames = Object.keys(THEMES) as ThemeName[];
    const descriptions: Record<string, string> = {
      dark: 'Varsayılan koyu mavi', light: 'Açık tema',
      cyberpunk: 'Matrix / neon', retro: 'Retro turuncu',
      ocean: 'Okyanus mavisi', sunset: 'Gün batımı pembe',
    };
    const options = themeNames.map(name => ({
      value: name,
      label: `${name.padEnd(10)} — ${descriptions[name] ?? name}`,
    }));
    const selected = await select({ message: 'Tema seçin:', options });
    if (isCancel(selected)) return { output: chalk.gray('İptal edildi.') };
    setTheme(selected as ThemeName);
    saveConfig({ theme: selected as string });
    const colors = getThemeColors();
    const preview = [
      colors.navy('■ Ana'), colors.navyBright('■ İkincil'),
      colors.success('■ Başarı'), colors.warning('■ Uyarı'),
      colors.error('■ Hata'), colors.cmd('■ Komut'),
      colors.toolAccent('■ Araç'), colors.sparkle('■ Vurgu'),
    ].join('  ');
    return { output: `${colors.success('✓')} Tema: ${colors.navyBright(selected as string)}\n\n  ${preview}` };
  },

  geçmiş: async () => {
    const sessions = listSessions()
      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
      .slice(0, 20);

    if (sessions.length === 0) return { output: chalk.gray('Kayıtlı oturum yok.') };

    const options = sessions.map(s => {
      const date = new Date(s.updatedAt).toLocaleString('tr-TR', { dateStyle: 'short', timeStyle: 'short' });
      const tag = s.tag ? ` ${chalk.bgBlue.white(` ${s.tag} `)}` : '';
      return { value: s.id, label: `${chalk.dim(s.id.slice(0, 8))}  ${s.provider}/${s.model}${tag}  ${chalk.dim(date)}` };
    });

    const selected = await select({ message: 'Oturum seçin:', options });
    if (isCancel(selected)) return { output: chalk.gray('İptal edildi.') };

    return {
      output: chalk.green(`✓ Yeniden başlatılıyor...`),
      runAsUserMessage: `__RESUME__${selected as string}`,
    };
  },

  etiket: async (args, ctx) => {
    const tag = args.trim();
    if (!tag) return { output: chalk.dim('Kullanım: /etiket <isim>') };
    const ok = setSessionTag(ctx.getSessionId(), tag);
    return { output: ok ? chalk.green(`✓ Oturum etiketlendi: ${tag}`) : chalk.red('Hata: Oturum bulunamadı.') };
  },

  profil: async (args, ctx) => {
    const parts = args.trim().split(' ');
    const sub = parts[0];
    const cfg = loadConfig();
    const profiles = cfg.profiles || {};

    if (!sub || sub === 'liste') {
      const names = Object.keys(profiles);
      if (names.length === 0) return { output: chalk.dim('  Kayıtlı profil yok. /profil ekle <isim>') };
      const lines = [chalk.bold('👤 Kayıtlı Profiller:'), ''];
      for (const name of names) {
        const p = profiles[name];
        lines.push(`  • ${chalk.cyan(name.padEnd(15))} : ${p.provider} / ${p.model}`);
      }
      return { output: lines.join('\n') };
    }

    if (sub === 'ekle') {
      const name = parts[1];
      if (!name) return { output: chalk.red('Kullanım: /profil ekle <isim>') };
      const newProfiles = { ...profiles, [name]: { provider: ctx.currentProvider, model: ctx.currentModel } };
      saveConfig({ profiles: newProfiles });
      return { output: chalk.green(`✓ Profil eklendi: ${name}`) };
    }

    if (profiles[sub]) {
      const p = profiles[sub];
      await ctx.setProvider(p.provider);
      ctx.setModel(p.model);
      return { output: chalk.green(`✓ Profile geçildi: ${sub} (${p.provider}/${p.model})`) };
    }

    return { output: chalk.red(`Profil bulunamadı: ${sub}`) };
  },

  çıkış: async () => {
    return { output: '', shouldExit: true };
  },

  yapımcı: () => ({
    output: `
${chalk.bold.red('🐍 SETH v' + VERSION + ' — Strategic Exploitation & Tactical Hybrid')}

${chalk.bold.cyan('👨‍💻 Yapımcı:')} ${chalk.bold('Mustafa Kemal Çıngıl')}
${chalk.dim('GitHub:')} ${chalk.underline('https://github.com/MustafaKemal0146')}

${chalk.dim('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}

${chalk.yellow('🎓 Eğitim:')}
  • Bitlis Eren Üniversitesi Mühendislik Fakültesi
  • Bilgisayar Mühendisliği (2. sınıf)

${chalk.green('🔬 Uzmanlık Alanları:')}
  • Yapay Zeka Araştırmaları & Machine Learning
  • Computer Vision & RAG Tuning  
  • Modern Web Development (React, TypeScript)
  • Otomasyon ve Workflow Optimizasyonu
  • Siber Güvenlik Araçları

${chalk.blue('📊 İstatistikler:')}
  • 30+ Aktif Proje
  • 800+ Test Ortamı
  • 3+ Yıl Deneyim
  • GitHub'da Açık Kaynak Katkıları

${chalk.magenta('🌐 İletişim:')}
  • Web: ${chalk.underline('https://mustafakemalcingil.site')}
  • LinkedIn: ${chalk.underline('https://linkedin.com/in/mustafakemalcingil')}
  • E-posta: ${chalk.underline('ismustafakemal0146@gmail.com')}

${chalk.dim('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}

${chalk.red.bold('⚡ SETH')} — Teknoloji ile hayatı kolaylaştıran, etik hacker ruhuyla geliştirilmiş
otonom siber operasyon aracı. Bitlis'ten dünyaya açılan bir yapay zeka projesi.

${chalk.dim('Yanıt süresi: 24 saat içinde • Çalışma dili: Türkçe, İngilizce')}
`,
  }),

  // Geriye uyumluluk için eski komutlar (alias)
  yardim: (...args) => COMMANDS.yardım(...args),
  ozellikler: (...args) => COMMANDS.özellikler(...args),
  saglayici: (...args) => COMMANDS.sağlayıcı(...args),
  saglayicilar: (...args) => (COMMANDS as any).sağlayıcılar(...args),
  araclar: (...args) => COMMANDS.araçlar(...args),
  degistir: (...args) => COMMANDS.değiştir(...args),
  sikistir: (...args) => COMMANDS.sıkıştır(...args),
  repo_ozet: (...args) => COMMANDS.repo_özet(...args),
  nasilcalisir: (...args) => COMMANDS.nasılçalışır(...args),
  gecmis: (...args) => COMMANDS.geçmiş(...args),
  guncelle: (...args) => COMMANDS.güncelle(...args),
  istatistik: (...args) => COMMANDS.istatistikler(...args),
  rapor_pdf: (...args) => COMMANDS.rapor(...args),
  hafiza: (...args) => (COMMANDS as any)['hafıza'](...args),
  'hafiza-temizle': (...args) => (COMMANDS as any)['hafıza-temizle'](...args),
  baglam: (...args) => (COMMANDS as any)['bağlam'](...args),
  gorevler: (...args) => (COMMANDS as any)['görevler'](...args),
};

export async function executeCommand(input: string, ctx: CommandContext): Promise<CommandResult | null> {
  const { cmd, args } = parseCommand(input);
  const handler = COMMANDS[cmd];
  if (!handler) return { output: chalk.red(`  Bilinmeyen komut: /${cmd}`) };
  return handler(args, ctx);
}

export function parseCommand(input: string): { cmd: string; args: string } {
  const parts = input.trim().substring(1).split(/\s+/);
  const cmd = parts[0]!.toLowerCase();
  const args = parts.slice(1).join(' ');
  return { cmd, args };
}

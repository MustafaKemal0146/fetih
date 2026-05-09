/**
 * @fileoverview Shell tamamlama (bash/zsh/fish) kurulum scripti.
 * /kabuk-kurulum komutu tarafından çağrılır.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { writeFile, readFile, appendFile, mkdir } from 'node:fs/promises';

// ─── Bash completion script ───────────────────────────────────────────────────

const BASH_COMPLETION = `# Fetih bash completion
_fetih_complete() {
  local cur="\${COMP_WORDS[COMP_CWORD]}"
  local prev="\${COMP_WORDS[COMP_CWORD-1]}"
  local opts="--help --version --provider --model --auto --debug --headless"

  if [[ "\${cur}" == -* ]]; then
    COMPREPLY=( \$(compgen -W "\${opts}" -- "\${cur}") )
    return 0
  fi

  if [[ "\${prev}" == "--provider" || "\${prev}" == "-P" ]]; then
    COMPREPLY=( \$(compgen -W "ollama claude openai gemini groq deepseek mistral xai lmstudio openrouter" -- "\${cur}") )
    return 0
  fi

  COMPREPLY=( \$(compgen -f -- "\${cur}") )
}
complete -F _fetih_complete fetih
`;

// ─── Zsh completion script ────────────────────────────────────────────────────

const ZSH_COMPLETION = `# Fetih zsh completion
_fetih() {
  local -a opts
  opts=(
    '--help:Yardımı göster'
    '--version:Sürümü göster'
    '--provider:Sağlayıcı seç (ollama|claude|openai|gemini|groq)'
    '--model:Model adını belirt'
    '--auto:Tüm araç onaylarını otomatik kabul et'
    '--debug:Hata ayıklama modunu aç'
    '--headless:Etkileşimsiz mod (-p ile)'
  )
  _describe 'fetih seçenekleri' opts
}
compdef _fetih fetih
`;

// ─── Fish completion script ───────────────────────────────────────────────────

const FISH_COMPLETION = `# Fetih fish completion
complete -c fetih -s h -l help    -d 'Yardımı göster'
complete -c fetih -s V -l version -d 'Sürümü göster'
complete -c fetih      -l provider -d 'Sağlayıcı seç' -xa 'ollama claude openai gemini groq deepseek mistral xai lmstudio openrouter'
complete -c fetih      -l model    -d 'Model adını belirt'
complete -c fetih -s y -l auto    -d 'Tüm araç onaylarını otomatik kabul et'
complete -c fetih      -l debug   -d 'Hata ayıklama modunu aç'
complete -c fetih -s p -l prompt  -d 'Etkileşimsiz mod ile sorgu'
`;

// ─── Kurulum ──────────────────────────────────────────────────────────────────

export async function setupShellCompletion(): Promise<{ success: boolean; lines: string[] }> {
  const shell = (process.env.SHELL ?? '').toLowerCase();
  const home  = homedir();
  const fetihDir = join(home, '.fetih');
  const lines: string[] = [];

  await mkdir(fetihDir, { recursive: true });

  if (shell.includes('fish')) {
    const fishDir  = join(home, '.config', 'fish', 'completions');
    const fishFile = join(fishDir, 'fetih.fish');
    await mkdir(fishDir, { recursive: true });
    await writeFile(fishFile, FISH_COMPLETION, 'utf-8');
    lines.push(`✓ Fish tamamlama yazıldı: ${fishFile}`);
    lines.push('  Yeni terminal açtığında otomatik yüklenir.');

  } else if (shell.includes('zsh')) {
    const scriptPath = join(fetihDir, 'completion.zsh');
    await writeFile(scriptPath, ZSH_COMPLETION, 'utf-8');

    const rcPath   = join(home, '.zshrc');
    const existing = await readFile(rcPath, 'utf-8').catch(() => '');
    const marker   = '# Fetih shell tamamlama';

    if (!existing.includes(marker)) {
      await appendFile(rcPath, `\n${marker}\n[ -f ~/.fetih/completion.zsh ] && source ~/.fetih/completion.zsh\n`);
      lines.push(`✓ .zshrc güncellendi`);
    } else {
      lines.push(`  .zshrc zaten yapılandırılmış`);
    }
    lines.push(`✓ Zsh tamamlama yazıldı: ${scriptPath}`);
    lines.push('  Yeni terminal aç veya: source ~/.zshrc');

  } else {
    // Bash (default)
    const scriptPath = join(fetihDir, 'completion.bash');
    await writeFile(scriptPath, BASH_COMPLETION, 'utf-8');

    const rcPath   = join(home, '.bashrc');
    const existing = await readFile(rcPath, 'utf-8').catch(() => '');
    const marker   = '# Fetih shell tamamlama';

    if (!existing.includes(marker)) {
      await appendFile(rcPath, `\n${marker}\n[ -f ~/.fetih/completion.bash ] && source ~/.fetih/completion.bash\n`);
      lines.push(`✓ .bashrc güncellendi`);
    } else {
      lines.push(`  .bashrc zaten yapılandırılmış`);
    }
    lines.push(`✓ Bash tamamlama yazıldı: ${scriptPath}`);
    lines.push('  Yeni terminal aç veya: source ~/.bashrc');
  }

  lines.push('');
  lines.push('Kullanım: terminalde  fetih [Tab]  yazarak tamamlamayı test et.');
  return { success: true, lines };
}

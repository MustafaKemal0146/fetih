/**
 * Fetih Visual Engine — Gelişmiş görsel çıktı motoru
 * Progress bar, vulnerability card, section header, tool status formatlaması
 */

import chalk from 'chalk';

export const FetihColors = {
  // Temel renkler
  MATRIX_GREEN:    '\x1b[38;5;46m',
  NEON_BLUE:       '\x1b[38;5;51m',
  ELECTRIC_PURPLE: '\x1b[38;5;129m',
  CYBER_ORANGE:    '\x1b[38;5;208m',
  HACKER_RED:      '\x1b[38;5;196m',
  TERMINAL_GRAY:   '\x1b[38;5;240m',
  BRIGHT_WHITE:    '\x1b[97m',
  RESET:           '\x1b[0m',
  BOLD:            '\x1b[1m',
  DIM:             '\x1b[2m',
  // Durum renkleri
  SUCCESS:         '\x1b[38;5;46m',
  WARNING:         '\x1b[38;5;208m',
  ERROR:           '\x1b[38;5;196m',
  INFO:            '\x1b[38;5;51m',
  // Zafiyet seviyeleri
  VULN_CRITICAL:   '\x1b[48;5;124m\x1b[38;5;15m\x1b[1m',
  VULN_HIGH:       '\x1b[38;5;196m\x1b[1m',
  VULN_MEDIUM:     '\x1b[38;5;208m\x1b[1m',
  VULN_LOW:        '\x1b[38;5;226m',
  VULN_INFO:       '\x1b[38;5;51m',
  // Tool durum renkleri
  TOOL_RUNNING:    '\x1b[38;5;46m',
  TOOL_SUCCESS:    '\x1b[38;5;46m\x1b[1m',
  TOOL_FAILED:     '\x1b[38;5;196m\x1b[1m',
  TOOL_TIMEOUT:    '\x1b[38;5;208m\x1b[1m',
} as const;

export class VisualEngine {
  /** Güzel progress bar oluşturur */
  static progressBar(current: number, total: number, width = 40, label = ''): string {
    const pct = total === 0 ? 0 : Math.min(100, (current / total) * 100);
    const filled = Math.round(width * pct / 100);
    const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
    const prefix = label ? `${label}: ` : '';
    return `${prefix}${FetihColors.MATRIX_GREEN}[${bar}]${FetihColors.RESET} ${pct.toFixed(1)}%`;
  }

  /** Tool çalışma durumunu formatlar */
  static toolStatus(toolName: string, status: 'RUNNING' | 'SUCCESS' | 'FAILED' | 'TIMEOUT', target = '', progress = 0): string {
    const colors: Record<string, string> = {
      RUNNING: FetihColors.TOOL_RUNNING,
      SUCCESS: FetihColors.TOOL_SUCCESS,
      FAILED:  FetihColors.TOOL_FAILED,
      TIMEOUT: FetihColors.TOOL_TIMEOUT,
    };
    const color = colors[status] ?? FetihColors.INFO;
    let progressBar = '';
    if (progress > 0) {
      const filled = Math.round(20 * progress);
      progressBar = ` [${FetihColors.MATRIX_GREEN}${'█'.repeat(filled)}${'░'.repeat(20 - filled)}${FetihColors.RESET}] ${(progress * 100).toFixed(1)}%`;
    }
    return `${color}🔧 ${toolName.toUpperCase()}${FetihColors.RESET} | ${color}${status}${FetihColors.RESET}${target ? ` | ${FetihColors.BRIGHT_WHITE}${target}${FetihColors.RESET}` : ''}${progressBar}`;
  }

  /** Zafiyet kartı formatlar */
  static vulnerabilityCard(name: string, severity: string, description: string): string {
    const sevColors: Record<string, string> = {
      CRITICAL: FetihColors.VULN_CRITICAL,
      HIGH:     FetihColors.VULN_HIGH,
      MEDIUM:   FetihColors.VULN_MEDIUM,
      LOW:      FetihColors.VULN_LOW,
      INFO:     FetihColors.VULN_INFO,
    };
    const color = sevColors[severity.toUpperCase()] ?? FetihColors.INFO;
    return [
      `${color}┌─ 🚨 ZAFİYET TESPİT EDİLDİ ─────────────────────────────────────┐`,
      `│ ${FetihColors.BRIGHT_WHITE}${name.padEnd(60)}${color} │`,
      `│ ${FetihColors.TERMINAL_GRAY}Seviye: ${color}${severity.padEnd(52)}${color} │`,
      `│ ${FetihColors.TERMINAL_GRAY}${description.slice(0, 58).padEnd(58)}${color} │`,
      `└─────────────────────────────────────────────────────────────────┘${FetihColors.RESET}`,
    ].join('\n');
  }

  /** Bölüm başlığı oluşturur */
  static sectionHeader(title: string, icon = '🔥'): string {
    const line = '═'.repeat(70);
    return `\n${FetihColors.HACKER_RED}${line}${FetihColors.RESET}\n${FetihColors.HACKER_RED}${icon} ${title.toUpperCase()}${FetihColors.RESET}\n${FetihColors.HACKER_RED}${line}${FetihColors.RESET}`;
  }

  /** Hata kartı formatlar */
  static errorCard(errorType: string, toolName: string, errorMessage: string, recovery = ''): string {
    const lines = [
      `${FetihColors.ERROR}┌─ 🔥 HATA ───────────────────────────────────────────────────────┐`,
      `│ ${FetihColors.BRIGHT_WHITE}Tool: ${toolName.padEnd(55)}${FetihColors.ERROR} │`,
      `│ ${FetihColors.BRIGHT_WHITE}Tür:  ${errorType.padEnd(55)}${FetihColors.ERROR} │`,
      `│ ${FetihColors.BRIGHT_WHITE}Hata: ${errorMessage.slice(0, 53).padEnd(53)}${FetihColors.ERROR} │`,
    ];
    if (recovery) {
      lines.push(`│ ${FetihColors.ELECTRIC_PURPLE}Kurtarma: ${recovery.slice(0, 50).padEnd(50)}${FetihColors.ERROR} │`);
    }
    lines.push(`└─────────────────────────────────────────────────────────────────┘${FetihColors.RESET}`);
    return lines.join('\n');
  }

  /** Chalk ile renkli metin (tema uyumlu) */
  static highlight(text: string, type: 'red' | 'green' | 'yellow' | 'blue' | 'purple' = 'red'): string {
    const map = {
      red:    chalk.bgRed.white,
      green:  chalk.bgGreen.black,
      yellow: chalk.bgYellow.black,
      blue:   chalk.bgCyan.black,
      purple: chalk.bgMagenta.white,
    };
    return map[type](` ${text} `);
  }
}

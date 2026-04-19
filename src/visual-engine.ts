/**
 * Seth Visual Engine — Gelişmiş görsel çıktı motoru
 * Progress bar, vulnerability card, section header, tool status formatlaması
 */

import chalk from 'chalk';

export const SethColors = {
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
    return `${prefix}${SethColors.MATRIX_GREEN}[${bar}]${SethColors.RESET} ${pct.toFixed(1)}%`;
  }

  /** Tool çalışma durumunu formatlar */
  static toolStatus(toolName: string, status: 'RUNNING' | 'SUCCESS' | 'FAILED' | 'TIMEOUT', target = '', progress = 0): string {
    const colors: Record<string, string> = {
      RUNNING: SethColors.TOOL_RUNNING,
      SUCCESS: SethColors.TOOL_SUCCESS,
      FAILED:  SethColors.TOOL_FAILED,
      TIMEOUT: SethColors.TOOL_TIMEOUT,
    };
    const color = colors[status] ?? SethColors.INFO;
    let progressBar = '';
    if (progress > 0) {
      const filled = Math.round(20 * progress);
      progressBar = ` [${SethColors.MATRIX_GREEN}${'█'.repeat(filled)}${'░'.repeat(20 - filled)}${SethColors.RESET}] ${(progress * 100).toFixed(1)}%`;
    }
    return `${color}🔧 ${toolName.toUpperCase()}${SethColors.RESET} | ${color}${status}${SethColors.RESET}${target ? ` | ${SethColors.BRIGHT_WHITE}${target}${SethColors.RESET}` : ''}${progressBar}`;
  }

  /** Zafiyet kartı formatlar */
  static vulnerabilityCard(name: string, severity: string, description: string): string {
    const sevColors: Record<string, string> = {
      CRITICAL: SethColors.VULN_CRITICAL,
      HIGH:     SethColors.VULN_HIGH,
      MEDIUM:   SethColors.VULN_MEDIUM,
      LOW:      SethColors.VULN_LOW,
      INFO:     SethColors.VULN_INFO,
    };
    const color = sevColors[severity.toUpperCase()] ?? SethColors.INFO;
    return [
      `${color}┌─ 🚨 ZAFİYET TESPİT EDİLDİ ─────────────────────────────────────┐`,
      `│ ${SethColors.BRIGHT_WHITE}${name.padEnd(60)}${color} │`,
      `│ ${SethColors.TERMINAL_GRAY}Seviye: ${color}${severity.padEnd(52)}${color} │`,
      `│ ${SethColors.TERMINAL_GRAY}${description.slice(0, 58).padEnd(58)}${color} │`,
      `└─────────────────────────────────────────────────────────────────┘${SethColors.RESET}`,
    ].join('\n');
  }

  /** Bölüm başlığı oluşturur */
  static sectionHeader(title: string, icon = '🔥'): string {
    const line = '═'.repeat(70);
    return `\n${SethColors.HACKER_RED}${line}${SethColors.RESET}\n${SethColors.HACKER_RED}${icon} ${title.toUpperCase()}${SethColors.RESET}\n${SethColors.HACKER_RED}${line}${SethColors.RESET}`;
  }

  /** Hata kartı formatlar */
  static errorCard(errorType: string, toolName: string, errorMessage: string, recovery = ''): string {
    const lines = [
      `${SethColors.ERROR}┌─ 🔥 HATA ───────────────────────────────────────────────────────┐`,
      `│ ${SethColors.BRIGHT_WHITE}Tool: ${toolName.padEnd(55)}${SethColors.ERROR} │`,
      `│ ${SethColors.BRIGHT_WHITE}Tür:  ${errorType.padEnd(55)}${SethColors.ERROR} │`,
      `│ ${SethColors.BRIGHT_WHITE}Hata: ${errorMessage.slice(0, 53).padEnd(53)}${SethColors.ERROR} │`,
    ];
    if (recovery) {
      lines.push(`│ ${SethColors.ELECTRIC_PURPLE}Kurtarma: ${recovery.slice(0, 50).padEnd(50)}${SethColors.ERROR} │`);
    }
    lines.push(`└─────────────────────────────────────────────────────────────────┘${SethColors.RESET}`);
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

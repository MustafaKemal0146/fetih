/**
 * @fileoverview Keybinding konfigürasyon sistemi.
 * ~/.fetih/keybindings.json üzerinden özelleştirilebilir tuş kısayolları.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export interface Keybinding {
  /** Tuş adı (readline key.name): 'r', 'l', 'e', vb. */
  key: string;
  /** Ctrl tuşu gerekli mi? */
  ctrl?: boolean;
  /** Meta/Alt tuşu gerekli mi? */
  meta?: boolean;
  /** Shift tuşu gerekli mi? */
  shift?: boolean;
  /** Eylem adı — ACTIONS'ta tanımlı olmalı. */
  action: KeyAction;
}

export type KeyAction =
  | 'history-search'       // Ctrl+R: Geçmişte fuzzy ara
  | 'clear-screen'         // Ctrl+L: Ekranı temizle
  | 'external-editor'      // Ctrl+X Ctrl+E: Harici editör
  | 'abort'                // Ctrl+C: İptal
  | 'submit'               // Enter: Gönder
  | 'compact-history'      // Ctrl+K: Geçmişi sıkıştır
  | 'show-cost'            // Ctrl+P: Maliyet göster
  | 'vim-toggle';          // Ctrl+V: Vim modu aç/kapat

/** Varsayılan keybindinglar */
export const DEFAULT_KEYBINDINGS: Keybinding[] = [
  { key: 'r', ctrl: true, action: 'history-search' },
  { key: 'l', ctrl: true, action: 'clear-screen' },
  { key: 'x', ctrl: true, action: 'external-editor' }, // X+E sequence handled separately
];

/**
 * ~/.fetih/keybindings.json yükle; yoksa varsayılan döndür.
 */
export function loadKeybindings(): Keybinding[] {
  const path = join(homedir(), '.fetih', 'keybindings.json');
  if (!existsSync(path)) return DEFAULT_KEYBINDINGS;

  try {
    const raw = JSON.parse(readFileSync(path, 'utf-8')) as unknown;
    if (!Array.isArray(raw)) return DEFAULT_KEYBINDINGS;

    const bindings: Keybinding[] = [];
    for (const item of raw) {
      if (typeof item?.key === 'string' && typeof item?.action === 'string') {
        bindings.push({
          key: item.key,
          ctrl: Boolean(item.ctrl),
          meta: Boolean(item.meta),
          shift: Boolean(item.shift),
          action: item.action as KeyAction,
        });
      }
    }
    // Merge with defaults (user bindings take priority)
    const userKeys = new Set(bindings.map(b => `${b.ctrl ? 'ctrl+' : ''}${b.key}`));
    for (const def of DEFAULT_KEYBINDINGS) {
      const k = `${def.ctrl ? 'ctrl+' : ''}${def.key}`;
      if (!userKeys.has(k)) bindings.push(def);
    }
    return bindings;
  } catch {
    return DEFAULT_KEYBINDINGS;
  }
}

/**
 * Bir key event'in hangi action'a karşılık geldiğini bul.
 */
export function resolveAction(
  key: { name: string; ctrl?: boolean; meta?: boolean; shift?: boolean },
  bindings: Keybinding[],
): KeyAction | null {
  for (const b of bindings) {
    if (
      b.key === key.name &&
      (b.ctrl ?? false) === (key.ctrl ?? false) &&
      (b.meta ?? false) === (key.meta ?? false) &&
      (b.shift ?? false) === (key.shift ?? false)
    ) {
      return b.action;
    }
  }
  return null;
}

/**
 * Keybinding tablosunu okunabilir string olarak formatla.
 */
export function formatKeybindingsTable(bindings: Keybinding[]): string {
  const lines: string[] = ['  Tuş Kısayolları\n  ' + '─'.repeat(40)];
  for (const b of bindings) {
    const keyStr = [b.ctrl ? 'Ctrl' : '', b.meta ? 'Alt' : '', b.shift ? 'Shift' : '', b.key.toUpperCase()]
      .filter(Boolean)
      .join('+');
    lines.push(`  ${keyStr.padEnd(20)} → ${b.action}`);
  }
  lines.push(`\n  Özelleştirmek için: ~/.fetih/keybindings.json`);
  return lines.join('\n');
}

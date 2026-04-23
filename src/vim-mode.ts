/**
 * @fileoverview Vim mode state machine for readline — INSERT / NORMAL mods.
 * NORMAL modda temel cursor hareketi, operatörler (d/c/y), dot-repeat.
 */

import type { Interface as ReadlineInterface } from 'node:readline';

export type VimState = 'INSERT' | 'NORMAL';

interface VimHandler {
  handleKey(str: string | undefined, key: { name: string; ctrl?: boolean; meta?: boolean; shift?: boolean }): boolean;
  getMode(): VimState;
}

/**
 * createVimHandler — readline arayüzüne vim modu ekler.
 * Tuşları yakala: true döndürürse readline'a iletilmez.
 */
export function createVimHandler(rl: ReadlineInterface): VimHandler {
  let mode: VimState = 'INSERT';
  let pendingOp = ''; // bekleyen operatör (d, c, y)
  let lastAction = ''; // dot-repeat için

  function getLine(): string {
    return (rl as any).line ?? '';
  }

  function setLine(text: string, cursorPos?: number): void {
    // readline'ın iç durumunu güncelle
    (rl as any).line = text;
    const pos = cursorPos !== undefined ? cursorPos : text.length;
    (rl as any).cursor = Math.max(0, Math.min(pos, text.length));
    (rl as any)._refreshLine?.();
  }

  function moveCursor(delta: number): void {
    const line = getLine();
    const cur = (rl as any).cursor ?? 0;
    const newPos = Math.max(0, Math.min(cur + delta, line.length));
    (rl as any).cursor = newPos;
    (rl as any)._refreshLine?.();
  }

  function wordForward(): void {
    const line = getLine();
    let pos = (rl as any).cursor ?? 0;
    // Skip current word
    while (pos < line.length && line[pos] !== ' ') pos++;
    // Skip spaces
    while (pos < line.length && line[pos] === ' ') pos++;
    (rl as any).cursor = pos;
    (rl as any)._refreshLine?.();
  }

  function wordBackward(): void {
    const line = getLine();
    let pos = (rl as any).cursor ?? 0;
    if (pos > 0) pos--;
    // Skip spaces
    while (pos > 0 && line[pos] === ' ') pos--;
    // Skip word
    while (pos > 0 && line[pos - 1] !== ' ') pos--;
    (rl as any).cursor = pos;
    (rl as any)._refreshLine?.();
  }

  function wordEnd(): void {
    const line = getLine();
    let pos = (rl as any).cursor ?? 0;
    if (pos < line.length - 1) pos++;
    // Skip spaces
    while (pos < line.length - 1 && line[pos] === ' ') pos++;
    // Go to end of word
    while (pos < line.length - 1 && line[pos + 1] !== ' ') pos++;
    (rl as any).cursor = pos;
    (rl as any)._refreshLine?.();
  }

  function deleteToEnd(): void {
    const line = getLine();
    const pos = (rl as any).cursor ?? 0;
    setLine(line.slice(0, pos), pos);
  }

  function deleteChar(): void {
    const line = getLine();
    const pos = (rl as any).cursor ?? 0;
    if (pos < line.length) {
      setLine(line.slice(0, pos) + line.slice(pos + 1), pos);
    }
  }

  function deleteWord(): void {
    const line = getLine();
    let pos = (rl as any).cursor ?? 0;
    const start = pos;
    while (pos < line.length && line[pos] !== ' ') pos++;
    while (pos < line.length && line[pos] === ' ') pos++;
    setLine(line.slice(0, start) + line.slice(pos), start);
  }

  function setMode(m: VimState): void {
    mode = m;
    // Cursor şeklini değiştir (destekleyen terminallerde)
    if (m === 'NORMAL') {
      process.stdout.write('\x1b[2 q'); // block cursor
    } else {
      process.stdout.write('\x1b[6 q'); // beam cursor
    }
    (rl as any)._refreshLine?.();
  }

  return {
    getMode() { return mode; },

    handleKey(str, key): boolean {
      if (mode === 'INSERT') {
        if (key.name === 'escape') {
          setMode('NORMAL');
          pendingOp = '';
          // Move cursor back one if not at start
          const pos = (rl as any).cursor ?? 0;
          if (pos > 0) moveCursor(-1);
          return true;
        }
        return false; // Let readline handle it
      }

      // ── NORMAL mode ──────────────────────────────────────────────────────────

      // Enter insert mode
      if (key.name === 'i') {
        setMode('INSERT');
        pendingOp = '';
        lastAction = 'i';
        return true;
      }
      if (key.name === 'a') {
        moveCursor(1);
        setMode('INSERT');
        pendingOp = '';
        lastAction = 'a';
        return true;
      }
      if (key.name === 'A') {
        const line = getLine();
        setLine(line, line.length);
        setMode('INSERT');
        pendingOp = '';
        return true;
      }
      if (key.name === 'o') {
        // Open new line (submit current + go to insert)
        setMode('INSERT');
        return true;
      }

      // Cursor movement
      if (key.name === 'h') { moveCursor(-1); return true; }
      if (key.name === 'l') { moveCursor(1); return true; }
      if (key.name === 'left') { moveCursor(-1); return true; }
      if (key.name === 'right') { moveCursor(1); return true; }

      // Word motions
      if (key.name === 'w') { wordForward(); return true; }
      if (key.name === 'b') { wordBackward(); return true; }
      if (key.name === 'e') { wordEnd(); return true; }

      // Line motions
      if (key.name === '0' && !pendingOp) {
        (rl as any).cursor = 0;
        (rl as any)._refreshLine?.();
        return true;
      }
      if (str === '$') {
        const line = getLine();
        (rl as any).cursor = Math.max(0, line.length - 1);
        (rl as any)._refreshLine?.();
        return true;
      }

      // Delete operations
      if (key.name === 'x') {
        deleteChar();
        lastAction = 'x';
        return true;
      }
      if (key.name === 'd') {
        if (pendingOp === 'd') {
          // dd — delete whole line
          setLine('', 0);
          pendingOp = '';
          lastAction = 'dd';
        } else {
          pendingOp = 'd';
          setTimeout(() => { pendingOp = ''; }, 1000);
        }
        return true;
      }
      if (pendingOp === 'd' && key.name === 'w') {
        deleteWord();
        pendingOp = '';
        lastAction = 'dw';
        return true;
      }
      if (pendingOp === 'd' && str === '$') {
        deleteToEnd();
        pendingOp = '';
        lastAction = 'd$';
        return true;
      }

      // Change operations (delete + insert)
      if (key.name === 'c') {
        if (pendingOp === 'c') {
          setLine('', 0);
          setMode('INSERT');
          pendingOp = '';
          lastAction = 'cc';
        } else {
          pendingOp = 'c';
          setTimeout(() => { pendingOp = ''; }, 1000);
        }
        return true;
      }
      if (pendingOp === 'c' && key.name === 'w') {
        deleteWord();
        setMode('INSERT');
        pendingOp = '';
        lastAction = 'cw';
        return true;
      }

      // Clear line
      if (str === 'S' || (key.name === 's')) {
        setLine('', 0);
        setMode('INSERT');
        lastAction = 'S';
        return true;
      }

      // Dot-repeat (simplified — repeats last delete action)
      if (str === '.') {
        if (lastAction === 'x') deleteChar();
        else if (lastAction === 'dw') deleteWord();
        else if (lastAction === 'd$') deleteToEnd();
        return true;
      }

      // Escape in normal mode — clear pending op
      if (key.name === 'escape') {
        pendingOp = '';
        return true;
      }

      // Block all other non-navigation keys in NORMAL mode
      return true;
    },
  };
}

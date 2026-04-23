/**
 * @fileoverview PTY mod paylaşımlı durumu.
 * Shell aracı PTY başlattığında stdin akışını REPL yerine PTY'ye yönlendirmek için kullanılır.
 */

/** PTY aktif mi — stdin bu süreçte PTY'ye yönlendiriliyor */
export let ptyModeActive = false;

/** PTY'ye yazma callback'i */
export let ptyInputWriter: ((data: string) => void) | null = null;

/** PTY moduna gir: stdin artık PTY'ye gider */
export function enterPtyMode(writer: (data: string) => void): void {
  ptyModeActive = true;
  ptyInputWriter = writer;
}

/** PTY modundan çık: stdin tekrar REPL'e döner */
export function exitPtyMode(): void {
  ptyModeActive = false;
  ptyInputWriter = null;
}

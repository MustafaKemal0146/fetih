/**
 * @fileoverview Seth CTF Shared Utilities
 * ctf-solver, ctf-stego, ctf-file-analyzer tarafından ortak kullanılan yardımcı fonksiyonlar.
 */

/** Flag pattern'ı içeriyor mu? */
export function looksLikeFlag(s: string): boolean {
  return /flag\{[^}]+\}/i.test(s) || /ctf\{[^}]+\}/i.test(s);
}

/** String veya string dizisi içindeki tüm flag'leri döndürür */
export function findFlags(input: string | string[]): string[] {
  const s = Array.isArray(input) ? input.join('\n') : input;
  const matches = s.match(/(?:flag|ctf)\{[^}]+\}/gi);
  return matches ? [...new Set(matches)] : [];
}

/** Printable ASCII oranı threshold'u geçiyor mu? */
export function isPrintableAscii(s: string, threshold = 0.85): boolean {
  if (!s.length) return false;
  const ok = s.split('').filter(c => {
    const code = c.charCodeAt(0);
    return (code >= 32 && code < 127) || code === 10 || code === 13 || code === 9;
  }).length;
  return ok / s.length >= threshold;
}

/** Buffer'dan 4+ karakter uzunluğundaki printable ASCII string'leri çıkarır */
export function extractStrings(buf: Buffer, minLen = 4): string[] {
  const results: string[] = [];
  let current = '';
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i]!;
    if (c >= 0x20 && c < 0x7F) {
      current += String.fromCharCode(c);
    } else {
      if (current.length >= minLen) results.push(current);
      current = '';
    }
  }
  if (current.length >= minLen) results.push(current);
  return results;
}

/** Magic bytes ile dosya türünü tespit eder */
export function detectMagicType(buf: Buffer): string {
  const MAGIC_SIGNATURES: Array<{ bytes: number[]; type: string }> = [
    { bytes: [0xFF, 0xD8, 0xFF],             type: 'JPEG' },
    { bytes: [0x89, 0x50, 0x4E, 0x47],       type: 'PNG' },
    { bytes: [0x47, 0x49, 0x46, 0x38],       type: 'GIF' },
    { bytes: [0x25, 0x50, 0x44, 0x46],       type: 'PDF' },
    { bytes: [0x50, 0x4B, 0x03, 0x04],       type: 'ZIP' },
    { bytes: [0x52, 0x61, 0x72, 0x21],       type: 'RAR' },
    { bytes: [0x7F, 0x45, 0x4C, 0x46],       type: 'ELF' },
    { bytes: [0x4D, 0x5A],                   type: 'PE/EXE' },
    { bytes: [0x1F, 0x8B],                   type: 'GZIP' },
    { bytes: [0x42, 0x4D],                   type: 'BMP' },
    { bytes: [0x49, 0x44, 0x33],             type: 'MP3' },
    { bytes: [0xA1, 0xB2, 0xC3, 0xD4],       type: 'PCAP' },
    { bytes: [0xD4, 0xC3, 0xB2, 0xA1],       type: 'PCAP' },
    { bytes: [0x0A, 0x0D, 0x0D, 0x0A],       type: 'PCAPNG' },
  ];
  for (const sig of MAGIC_SIGNATURES) {
    if (sig.bytes.every((b, i) => buf[i] === b)) return sig.type;
  }
  if (buf.length > 8 && buf.slice(4, 8).toString('ascii') === 'ftyp') return 'MP4';
  return 'UNKNOWN';
}

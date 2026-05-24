/**
 * @fileoverview Fetih CTF AES Helper — ECB pattern detect, CBC bit flip rehberi,
 * padding oracle attack template.
 */

import type { ToolDefinition, ToolResult } from '../../types.js';
import { createDecipheriv } from 'crypto';

// ─── ECB Pattern Detection ───────────────────────────────────────────────────

export interface EcbAnalysis {
  isLikelyEcb: boolean;
  totalBlocks: number;
  uniqueBlocks: number;
  duplicateBlocks: number;
  duplicateRatio: number;
  duplicates: Array<{ blockHex: string; count: number }>;
}

export function detectEcb(ciphertext: Buffer): EcbAnalysis {
  const blockSize = 16;
  if (ciphertext.length < blockSize * 2) {
    return { isLikelyEcb: false, totalBlocks: 0, uniqueBlocks: 0, duplicateBlocks: 0, duplicateRatio: 0, duplicates: [] };
  }
  const blockCount = Math.floor(ciphertext.length / blockSize);
  const blockMap = new Map<string, number>();
  for (let i = 0; i < blockCount; i++) {
    const block = ciphertext.slice(i * blockSize, (i + 1) * blockSize).toString('hex');
    blockMap.set(block, (blockMap.get(block) ?? 0) + 1);
  }
  const duplicates: Array<{ blockHex: string; count: number }> = [];
  let duplicateBlocks = 0;
  for (const [block, count] of blockMap.entries()) {
    if (count > 1) {
      duplicates.push({ blockHex: block, count });
      duplicateBlocks += count;
    }
  }
  duplicates.sort((a, b) => b.count - a.count);
  const ratio = duplicateBlocks / blockCount;
  return {
    isLikelyEcb: duplicates.length > 0 && ratio >= 0.05,
    totalBlocks: blockCount,
    uniqueBlocks: blockMap.size,
    duplicateBlocks,
    duplicateRatio: ratio,
    duplicates: duplicates.slice(0, 10),
  };
}

// ─── CBC Bit-flipping Rehberi ────────────────────────────────────────────────

export function cbcBitFlipGuide(): string {
  return [
    '# CBC Bit-Flipping Saldırı Rehberi',
    '',
    'Sen plaintext\'in N. byte\'ını değiştirmek istiyorsun (admin=true gibi).',
    'CBC formülü: P[i] = D(C[i]) XOR C[i-1]',
    'Yani C[i-1]\'i değiştirirsek P[i] değişir (ama C[i-1]\'in plaintext\'i bozulur).',
    '',
    'Adımlar:',
    '1. Mevcut plaintext\'in i. byte\'ını bil (X)',
    '2. Hedef plaintext byte\'ı belirle (Y)',
    '3. Önceki block C[i-1]\'in aynı offset\'ini değiştir:',
    '   new_C[i-1][j] = old_C[i-1][j] XOR X XOR Y',
    '4. Server tampered ciphertext\'i decrypt edince i. byte = Y olur',
    '',
    '# Pwntools örneği:',
    'from pwn import xor',
    'tampered = bytearray(ct)',
    'tampered[block_idx*16 + offset] ^= ord(known_p) ^ ord(target_p)',
    '',
    'Not: Bu saldırı önceki block\'un plaintext\'ini bozar (büyük ihtimal random byte).',
    'Server o block\'u kontrol etmiyorsa bypass çalışır.',
  ].join('\n');
}

// ─── Padding Oracle Attack Template ──────────────────────────────────────────

export function paddingOracleTemplate(targetUrl: string): string {
  return [
    '# Padding Oracle Attack Template (Python)',
    '',
    'Server PKCS#7 padding hatasını gösteriyorsa (200/500 fark, hata mesajı, vb.):',
    '',
    'from typing import Callable',
    'import requests',
    '',
    `TARGET = "${targetUrl}"`,
    'BLOCK_SIZE = 16',
    '',
    'def is_padding_valid(iv: bytes, block: bytes) -> bool:',
    '    """Server\'a iv+block gönder, padding hatası yoksa True dön"""',
    '    payload = (iv + block).hex()',
    '    r = requests.get(f"{TARGET}?ct={payload}", timeout=5)',
    '    # Burayı server response\'una göre ayarla:',
    '    return "PaddingException" not in r.text and r.status_code == 200',
    '',
    'def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:',
    '    """Tek bir block\'u decrypt et"""',
    '    intermediate = bytearray(BLOCK_SIZE)',
    '    plaintext = bytearray(BLOCK_SIZE)',
    '    for i in range(BLOCK_SIZE - 1, -1, -1):',
    '        pad_value = BLOCK_SIZE - i',
    '        for guess in range(256):',
    '            tampered_iv = bytearray(BLOCK_SIZE)',
    '            tampered_iv[i] = guess',
    '            for j in range(i+1, BLOCK_SIZE):',
    '                tampered_iv[j] = intermediate[j] ^ pad_value',
    '            if is_padding_valid(bytes(tampered_iv), target_block):',
    '                intermediate[i] = guess ^ pad_value',
    '                plaintext[i] = intermediate[i] ^ prev_block[i]',
    '                break',
    '    return bytes(plaintext)',
    '',
    '# Kullanım:',
    'ciphertext = bytes.fromhex("...")',
    'plaintext = b""',
    'for i in range(0, len(ciphertext) - BLOCK_SIZE, BLOCK_SIZE):',
    '    prev = ciphertext[i:i+BLOCK_SIZE]',
    '    curr = ciphertext[i+BLOCK_SIZE:i+2*BLOCK_SIZE]',
    '    plaintext += decrypt_block(prev, curr)',
    'print(plaintext)',
  ].join('\n');
}

// ─── ECB Decrypt (key biliniyorsa) ───────────────────────────────────────────

export function aesEcbDecrypt(ciphertext: Buffer, key: Buffer): { ok: boolean; plaintext: string; error?: string } {
  if (![16, 24, 32].includes(key.length)) {
    return { ok: false, plaintext: '', error: `Geçersiz key uzunluğu: ${key.length} (16/24/32 bekleniyor)` };
  }
  try {
    const algo = key.length === 16 ? 'aes-128-ecb' : key.length === 24 ? 'aes-192-ecb' : 'aes-256-ecb';
    const decipher = createDecipheriv(algo, key, null);
    decipher.setAutoPadding(false);
    const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return { ok: true, plaintext: out.toString('utf8') };
  } catch (err) {
    return { ok: false, plaintext: '', error: String(err).slice(0, 200) };
  }
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfAesHelperTool: ToolDefinition = {
  name: 'ctf_aes_helper',
  description:
    'CTF AES analiz: ecb_detect (16-byte block tekrar pattern\'i), ecb_decrypt (key ile çöz), ' +
    'cbc_flip_guide (CBC bit-flipping rehberi), padding_oracle (Python attack template). ' +
    'Şifreli metin ECB modu mu kontrolü, manuel exploit script üretimi.',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['ecb_detect', 'ecb_decrypt', 'cbc_flip_guide', 'padding_oracle'] },
      ciphertext: { type: 'string', description: 'Hex veya base64 ciphertext (ecb_detect/ecb_decrypt)' },
      ciphertextEncoding: { type: 'string', enum: ['hex', 'base64'], description: 'Varsayılan hex' },
      key: { type: 'string', description: 'ecb_decrypt için key (hex)' },
      url: { type: 'string', description: 'padding_oracle için hedef URL' },
    },
    required: ['action'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const action = String(input['action'] ?? '');

    switch (action) {
      case 'ecb_detect': {
        const ct = String(input['ciphertext'] ?? '');
        if (!ct) return { output: 'ciphertext gerekli', isError: true };
        const enc = String(input['ciphertextEncoding'] ?? 'hex') as 'hex' | 'base64';
        const buf = Buffer.from(ct.replace(/\s/g, ''), enc);
        const r = detectEcb(buf);
        const lines = [
          '┌─ ECB DETECTION ─────────────────────────────────────────────┐',
          `│ Toplam block (16B): ${r.totalBlocks}`,
          `│ Benzersiz block   : ${r.uniqueBlocks}`,
          `│ Tekrar block      : ${r.duplicateBlocks} (%${(r.duplicateRatio * 100).toFixed(1)})`,
          `│ Sonuç             : ${r.isLikelyEcb ? '⚠️  ECB MUHTEMELEN' : 'Muhtemelen CBC/CTR'}`,
          '└─────────────────────────────────────────────────────────────┘',
        ];
        if (r.duplicates.length > 0) {
          lines.push('\nTekrar eden block\'lar:');
          r.duplicates.forEach((d, i) => lines.push(`  [${i + 1}] ${d.blockHex} × ${d.count}`));
        }
        return { output: lines.join('\n'), isError: false };
      }
      case 'ecb_decrypt': {
        const ct = String(input['ciphertext'] ?? '');
        const key = String(input['key'] ?? '');
        if (!ct || !key) return { output: 'ciphertext ve key gerekli', isError: true };
        const enc = String(input['ciphertextEncoding'] ?? 'hex') as 'hex' | 'base64';
        const ctBuf = Buffer.from(ct.replace(/\s/g, ''), enc);
        const keyBuf = Buffer.from(key.replace(/\s/g, ''), 'hex');
        const r = aesEcbDecrypt(ctBuf, keyBuf);
        return r.ok
          ? { output: `Plaintext (utf8):\n${r.plaintext}`, isError: false }
          : { output: `Hata: ${r.error}`, isError: true };
      }
      case 'cbc_flip_guide':
        return { output: cbcBitFlipGuide(), isError: false };
      case 'padding_oracle': {
        const url = String(input['url'] ?? '<TARGET_URL>');
        return { output: paddingOracleTemplate(url), isError: false };
      }
      default:
        return { output: `Bilinmeyen eylem: ${action}`, isError: true };
    }
  },
};

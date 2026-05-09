/**
 * @fileoverview image_analyze tool — VLM (Vision LLM) ile görsel analiz.
 * Yerel görsel dosyasını base64 olarak aktif provider'a yollar; provider vision
 * destekliyorsa metin yanıtı, desteklemiyorsa rehberlik döndürür.
 *
 * CTF kullanımı: spektogram okuma, captcha çözümü, fotoğraftaki kod/QR/yazı,
 * gizli/silik metin tespiti.
 */

import { existsSync, readFileSync } from 'fs';
import { extname } from 'path';
import type { ToolDefinition, ToolResult, ChatMessage, ContentBlock } from '../types.js';
import { loadConfig } from '../config/settings.js';
import { createProvider } from '../providers/base.js';

const SUPPORTED_EXT: Record<string, 'image/jpeg' | 'image/png' | 'image/gif' | 'image/webp'> = {
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png':  'image/png',
  '.gif':  'image/gif',
  '.webp': 'image/webp',
};

const MAX_IMAGE_BYTES = 8 * 1024 * 1024; // 8 MB — VLM kotaları için makul üst sınır

export const imageAnalyzeTool: ToolDefinition = {
  name: 'image_analyze',
  description:
    'Bir görsel dosyasını aktif vision-capable LLM\'e (Anthropic, OpenAI, Google) yollar ' +
    've sorulan soruyu yanıtlatır. CTF için: spektogram okuma, captcha çözümü, ' +
    'fotoğraftaki yazı/kod/QR tespiti, gizli/silik metin okuma. ' +
    'JPEG/PNG/GIF/WebP destekler, max 8 MB.',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Analiz edilecek görsel dosyanın tam path\'i' },
      prompt: {
        type: 'string',
        description:
          'Vision modeline sorulacak soru. Örn: "Bu görselde flag\\{...\\} var mı?", ' +
          '"Bu spektogramda metin/morse görüyor musun?", "Captcha metnini oku".',
      },
    },
    required: ['path'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const path = String(input['path'] ?? '').trim();
    const prompt = String(
      input['prompt'] ?? 'Bu görselde ne görüyorsun? Yazı, kod, flag{...}, QR veya gizli metin var mı?',
    );

    if (!path) return { output: 'Hata: path boş olamaz.', isError: true };
    if (!existsSync(path)) return { output: `Dosya bulunamadı: ${path}`, isError: true };

    const ext = extname(path).toLowerCase();
    const mediaType = SUPPORTED_EXT[ext];
    if (!mediaType) {
      return {
        output: `Desteklenmeyen uzantı: ${ext}. Desteklenenler: ${Object.keys(SUPPORTED_EXT).join(', ')}`,
        isError: true,
      };
    }

    const buf = readFileSync(path);
    if (buf.byteLength > MAX_IMAGE_BYTES) {
      return {
        output: `Görsel çok büyük (${(buf.byteLength / 1024 / 1024).toFixed(1)} MB). Max ${MAX_IMAGE_BYTES / 1024 / 1024} MB.`,
        isError: true,
      };
    }
    const base64 = buf.toString('base64');

    const config = loadConfig();
    const provider = await createProvider(config.defaultProvider, config);

    if (!provider.supportsVision) {
      return {
        output:
          `Aktif provider (${provider.name}) vision desteklemiyor. ` +
          'anthropic, openai veya google\'a geç: /provider <ad>',
        isError: true,
      };
    }

    const userContent: ContentBlock[] = [
      { type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } },
      { type: 'text', text: prompt },
    ];
    const messages: ChatMessage[] = [{ role: 'user', content: userContent }];

    try {
      const response = await provider.chat(messages, {
        model: config.defaultModel,
        maxTokens: 1024,
        temperature: 0.2,
      });
      const text = response.content
        .filter(b => b.type === 'text')
        .map(b => (b as { text: string }).text)
        .join('\n')
        .trim();

      return {
        output: text || '(model boş yanıt döndürdü)',
        isError: false,
      };
    } catch (err) {
      return {
        output: `Vision çağrısı başarısız: ${err instanceof Error ? err.message : String(err)}`,
        isError: true,
      };
    }
  },
};

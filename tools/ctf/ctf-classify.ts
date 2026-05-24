/**
 * @fileoverview Fetih CTF Challenge Classifier — challenge metni alır,
 * kategori tahmin eder ve önerilen tool zincirini döner.
 */

import type { ToolDefinition, ToolResult } from '../../types.js';

export type CtfCategory =
  | 'crypto' | 'pwn' | 'reverse' | 'forensics' | 'web' | 'stego'
  | 'osint' | 'misc' | 'mobile' | 'hash' | 'jwt' | 'unknown';

export interface ClassifyResult {
  category: CtfCategory;
  confidence: number; // 0-100
  matched: string[];
  recommendedTools: string[];
  reasoning: string;
}

interface Pattern {
  category: CtfCategory;
  weight: number;
  patterns: RegExp[];
  keywords?: string[];
}

const PATTERNS: Pattern[] = [
  {
    category: 'pwn',
    weight: 25,
    patterns: [/buffer\s*overflow/i, /shellcode/i, /rop\s*chain/i, /format\s*string/i, /pwn/i, /exploit\s*me/i, /\bnc\s+\S+\s+\d+/, /libc/i, /gdb/i, /canary/i],
    keywords: ['pwn', 'overflow', 'shellcode', 'rop', 'libc'],
  },
  {
    category: 'reverse',
    weight: 22,
    patterns: [/reverse\s*engineer/i, /reverse[\s-]?eng/i, /\b(elf|binary)\b/i, /disassembl/i, /decompil/i, /ghidra/i, /ida\s*pro/i, /radare/i, /\.exe\b/, /static\s*analy/i],
    keywords: ['reverse', 'rev', 'binary', 'elf', 'pe'],
  },
  {
    category: 'crypto',
    weight: 20,
    patterns: [/\brsa\b/i, /\baes\b/i, /\bdes\b/i, /encrypt/i, /decrypt/i, /cipher/i, /key/i, /\bp\s*=\s*\d+/, /\bq\s*=\s*\d+/, /modulus/i, /xor/i, /caesar/i, /vigenere/i],
    keywords: ['crypto', 'encryption', 'cipher'],
  },
  {
    category: 'web',
    weight: 20,
    patterns: [/https?:\/\//, /\?id=/, /sql\s*inject/i, /xss/i, /lfi/i, /sssrf/i, /idor/i, /\bcookie\b/i, /jwt/i, /admin\s*panel/i, /robots\.txt/i, /\.git/i],
    keywords: ['web', 'http', 'url', 'cookie'],
  },
  {
    category: 'jwt',
    weight: 30,
    patterns: [/eyJ[A-Za-z0-9_-]+\./, /json\s*web\s*token/i, /\bjwt\b/i],
    keywords: ['jwt', 'token'],
  },
  {
    category: 'forensics',
    weight: 22,
    patterns: [/\.pcap(ng)?\b/i, /memory\s*dump/i, /volatility/i, /wireshark/i, /tshark/i, /forensic/i, /memdump/i, /\.raw\b/i, /\.vmem\b/i, /\.dmp\b/i],
    keywords: ['pcap', 'memory', 'forensics', 'dump'],
  },
  {
    category: 'stego',
    weight: 22,
    patterns: [/stegan/i, /\blsb\b/i, /steghide/i, /zsteg/i, /spectogram/i, /spectrogram/i, /hidden\s*in.*image/i, /\.png\b/i, /\.jpg\b/i, /\.wav\b/i, /\.mp3\b/i],
    keywords: ['stego', 'hidden', 'lsb'],
  },
  {
    category: 'mobile',
    weight: 30,
    patterns: [/\.apk\b/i, /\.ipa\b/i, /android/i, /\biOS\b/, /smali/i, /jadx/i, /apktool/i, /androidmanifest/i, /classes\.dex/i],
    keywords: ['apk', 'ipa', 'android', 'ios', 'mobile'],
  },
  {
    category: 'hash',
    weight: 25,
    patterns: [/\b[0-9a-f]{32}\b/i, /\b[0-9a-f]{40}\b/i, /\b[0-9a-f]{64}\b/i, /\b[0-9a-f]{128}\b/i, /\$2[abxy]\$/, /\$1\$/, /\$5\$/, /\$6\$/, /md5|sha1|sha256|sha512|bcrypt|ntlm/i],
    keywords: ['hash', 'crack'],
  },
  {
    category: 'osint',
    weight: 18,
    patterns: [/osint/i, /find\s*the\s*person/i, /\binstagram\b/i, /\btwitter\b/i, /\bgithub\b/i, /username/i, /metadata/i, /exif/i, /gps/i],
    keywords: ['osint', 'social media'],
  },
  {
    category: 'misc',
    weight: 10,
    patterns: [/misc/i, /\bquiz\b/i, /trivia/i, /puzzle/i],
    keywords: ['misc', 'puzzle'],
  },
];

const TOOL_RECOMMENDATIONS: Record<CtfCategory, string[]> = {
  crypto:    ['ctf_solver', 'ctf_rsa', 'ctf_aes_helper'],
  pwn:       ['ctf_pwn (checksec, cyclic)', 'ctf_binary_analyzer', 'pwn_session', 'interactive_session (gdb)'],
  reverse:   ['ctf_binary_analyzer', 'interactive_session (gdb)', 'ctf_pwn (checksec)'],
  forensics: ['ctf_forensics (pcap_parse, volatility)', 'ctf_file_analyzer'],
  web:       ['ctf_web_analyzer', 'ctf_jwt (varsa token)', 'web_fetch'],
  stego:     ['ctf_stego', 'ctf_audio_analyzer', 'image_analyze', 'ctf_file_analyzer'],
  osint:     ['ctf_file_analyzer (EXIF/GPS)', 'web_fetch', 'image_analyze'],
  hash:      ['ctf_hash', 'ctf_solver'],
  jwt:       ['ctf_jwt'],
  mobile:    ['ctf_mobile'],
  misc:      ['ctf_auto', 'ctf_solver'],
  unknown:   ['ctf_auto'],
};

export function classifyChallenge(text: string): ClassifyResult {
  const trimmed = text.trim();
  const scores = new Map<CtfCategory, { score: number; matched: string[] }>();

  for (const p of PATTERNS) {
    let score = 0;
    const matched: string[] = [];
    for (const re of p.patterns) {
      if (re.test(trimmed)) {
        score += p.weight;
        const m = trimmed.match(re);
        if (m) matched.push(m[0].slice(0, 40));
      }
    }
    if (p.keywords) {
      for (const kw of p.keywords) {
        if (new RegExp(`\\b${kw}\\b`, 'i').test(trimmed)) {
          score += 5;
          matched.push(`kw:${kw}`);
        }
      }
    }
    if (score > 0) {
      const existing = scores.get(p.category);
      scores.set(p.category, {
        score: (existing?.score ?? 0) + score,
        matched: [...(existing?.matched ?? []), ...matched],
      });
    }
  }

  if (scores.size === 0) {
    return {
      category: 'unknown',
      confidence: 0,
      matched: [],
      recommendedTools: TOOL_RECOMMENDATIONS.unknown,
      reasoning: 'Hiçbir kategori pattern eşleşmedi',
    };
  }

  const sorted = [...scores.entries()].sort((a, b) => b[1].score - a[1].score);
  const [top, second] = sorted;
  const confidence = Math.min(100, top![1].score);
  const reasoning = second
    ? `${top![0]} (${top![1].score}p) > ${second[0]} (${second[1].score}p)`
    : `${top![0]} (${top![1].score}p) tek eşleşme`;

  return {
    category: top![0],
    confidence,
    matched: top![1].matched.slice(0, 5),
    recommendedTools: TOOL_RECOMMENDATIONS[top![0]],
    reasoning,
  };
}

// ─── Tool Tanımı ─────────────────────────────────────────────────────────────

export const ctfClassifyTool: ToolDefinition = {
  name: 'ctf_classify',
  description:
    'CTF challenge metnini analiz et, kategori tahmin et ve önerilen tool zincirini dön. ' +
    'Bilinmeyen bir CTF challenge\'ı verildiğinde ilk adım: önce bunu çağır, ' +
    'sonra önerilen tool\'lardan başla. ' +
    'Kategoriler: crypto, pwn, reverse, forensics, web, stego, osint, hash, jwt, mobile, misc.',
  inputSchema: {
    type: 'object',
    properties: {
      text: { type: 'string', description: 'Challenge başlığı, açıklaması veya verilen ipucu metni' },
    },
    required: ['text'],
  },
  isDestructive: false,
  requiresConfirmation: false,

  async execute(input: Record<string, unknown>): Promise<ToolResult> {
    const text = String(input['text'] ?? '').trim();
    if (!text) return { output: 'text gerekli', isError: true };

    const r = classifyChallenge(text);
    const lines = [
      '┌─ CTF CLASSIFY ──────────────────────────────────────────────┐',
      `│ Kategori   : ${r.category.toUpperCase()}`,
      `│ Güven      : %${r.confidence}`,
      `│ Eşleşmeler : ${r.matched.join(', ').slice(0, 60)}`,
      `│ Karar      : ${r.reasoning}`,
      '└─────────────────────────────────────────────────────────────┘',
      '',
      'Önerilen tool zinciri (sırayla dene):',
      ...r.recommendedTools.map((t, i) => `  ${i + 1}. ${t}`),
    ];
    return { output: lines.join('\n'), isError: false };
  },
};

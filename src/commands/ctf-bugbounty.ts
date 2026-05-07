/**
 * Fetih CTF & Bug Bounty Workflow'ları
 * /ctf ve /bugbounty komutları için özel iş akışları
 */

export type CTFCategory = 'web' | 'crypto' | 'pwn' | 'forensics' | 'rev' | 'misc' | 'osint';
export type CTFDifficulty = 'easy' | 'medium' | 'hard' | 'insane' | 'unknown';

export interface CTFChallenge {
  name: string;
  category: CTFCategory;
  description: string;
  difficulty: CTFDifficulty;
  points?: number;
  url?: string;
  files?: string[];
}

export interface WorkflowStep {
  step: number;
  action: string;
  description: string;
  tools: string[];
  parallel: boolean;
  estimatedSeconds: number;
}

export interface CTFWorkflow {
  challenge: string;
  category: CTFCategory;
  difficulty: CTFDifficulty;
  steps: WorkflowStep[];
  suggestedTools: string[];
  estimatedSeconds: number;
  successProbability: number;
  fallbackStrategies: string[];
}

export interface BugBountyWorkflow {
  domain: string;
  phase: string;
  tools: Array<{ tool: string; params: Record<string, unknown> }>;
  estimatedSeconds: number;
  description: string;
}

// Kategori bazlı araç listesi
const CATEGORY_TOOLS: Record<CTFCategory, string[]> = {
  web:       ['httpx', 'katana', 'gobuster', 'sqlmap', 'dalfox', 'nuclei', 'ffuf', 'arjun'],
  crypto:    ['hashcat', 'john', 'hash-identifier', 'rsatool', 'factordb', 'sage'],
  pwn:       ['checksec', 'ghidra', 'pwntools', 'ropper', 'one-gadget', 'gdb-peda', 'angr'],
  forensics: ['binwalk', 'foremost', 'exiftool', 'steghide', 'volatility', 'wireshark', 'strings'],
  rev:       ['ghidra', 'radare2', 'strings', 'objdump', 'gdb', 'ltrace', 'strace'],
  misc:      ['base64', 'xxd', 'file', 'binwalk', 'qr-decoder'],
  osint:     ['sherlock', 'theHarvester', 'amass', 'subfinder', 'whois', 'dig', 'shodan'],
};

// Kategori bazlı workflow adımları
const CATEGORY_STEPS: Record<CTFCategory, WorkflowStep[]> = {
  web: [
    { step: 1, action: 'recon',          description: 'Hedef keşif ve teknoloji tespiti',    tools: ['httpx', 'whatweb'],          parallel: true,  estimatedSeconds: 300 },
    { step: 2, action: 'source_review',  description: 'Kaynak kod ve yorum analizi',          tools: ['manual'],                    parallel: false, estimatedSeconds: 600 },
    { step: 3, action: 'dir_enum',       description: 'Dizin ve dosya keşfi',                 tools: ['gobuster', 'dirsearch'],     parallel: true,  estimatedSeconds: 900 },
    { step: 4, action: 'param_discover', description: 'Parametre keşfi',                      tools: ['arjun', 'paramspider'],      parallel: true,  estimatedSeconds: 600 },
    { step: 5, action: 'vuln_scan',      description: 'Zafiyet taraması',                     tools: ['sqlmap', 'dalfox', 'nuclei'], parallel: true, estimatedSeconds: 1200 },
    { step: 6, action: 'exploit',        description: 'Zafiyet sömürüsü',                     tools: ['custom'],                    parallel: false, estimatedSeconds: 900 },
  ],
  crypto: [
    { step: 1, action: 'identify',       description: 'Şifre/hash tipi tespiti',              tools: ['hash-identifier', 'cipher-identifier'], parallel: false, estimatedSeconds: 300 },
    { step: 2, action: 'crack',          description: 'Otomatik kırma saldırısı',             tools: ['hashcat', 'john'],           parallel: true,  estimatedSeconds: 1800 },
    { step: 3, action: 'math_analysis',  description: 'Matematiksel analiz',                  tools: ['sage', 'python'],            parallel: false, estimatedSeconds: 1200 },
    { step: 4, action: 'freq_analysis',  description: 'Frekans analizi',                      tools: ['frequency-analysis'],        parallel: false, estimatedSeconds: 900 },
    { step: 5, action: 'verify',         description: 'Çözümü doğrula ve flag çıkar',         tools: ['manual'],                    parallel: false, estimatedSeconds: 300 },
  ],
  pwn: [
    { step: 1, action: 'binary_recon',   description: 'Binary analizi ve koruma tespiti',     tools: ['checksec', 'file', 'strings'], parallel: true, estimatedSeconds: 600 },
    { step: 2, action: 'static',         description: 'Statik analiz',                        tools: ['ghidra', 'radare2'],         parallel: true,  estimatedSeconds: 1800 },
    { step: 3, action: 'dynamic',        description: 'Dinamik analiz ve debug',              tools: ['gdb-peda', 'ltrace'],        parallel: false, estimatedSeconds: 1200 },
    { step: 4, action: 'exploit_dev',    description: 'Exploit geliştirme',                   tools: ['pwntools', 'ropper'],        parallel: false, estimatedSeconds: 2400 },
    { step: 5, action: 'test_local',     description: 'Lokal test',                           tools: ['gdb-peda'],                  parallel: false, estimatedSeconds: 600 },
    { step: 6, action: 'remote_exploit', description: 'Remote exploit çalıştır',              tools: ['pwntools'],                  parallel: false, estimatedSeconds: 600 },
  ],
  forensics: [
    { step: 1, action: 'file_analysis',  description: 'Dosya yapısı analizi',                 tools: ['file', 'exiftool', 'binwalk'], parallel: true, estimatedSeconds: 600 },
    { step: 2, action: 'stego',          description: 'Steganografi tespiti',                 tools: ['steghide', 'zsteg', 'stegsolve'], parallel: true, estimatedSeconds: 900 },
    { step: 3, action: 'memory',         description: 'Bellek analizi (varsa)',               tools: ['volatility'],                parallel: false, estimatedSeconds: 1800 },
    { step: 4, action: 'network',        description: 'Ağ trafiği analizi (varsa)',           tools: ['wireshark', 'tcpdump'],      parallel: false, estimatedSeconds: 1200 },
    { step: 5, action: 'correlate',      description: 'Bulguları ilişkilendir',               tools: ['manual'],                    parallel: false, estimatedSeconds: 600 },
  ],
  rev: [
    { step: 1, action: 'triage',         description: 'Binary sınıflandırma',                 tools: ['file', 'strings', 'checksec'], parallel: true, estimatedSeconds: 300 },
    { step: 2, action: 'unpack',         description: 'Packer tespiti ve açma',               tools: ['upx', 'detect-it-easy'],     parallel: false, estimatedSeconds: 600 },
    { step: 3, action: 'disassemble',    description: 'Disassembly ve decompile',             tools: ['ghidra', 'radare2'],         parallel: true,  estimatedSeconds: 2400 },
    { step: 4, action: 'dynamic',        description: 'Dinamik analiz',                       tools: ['gdb', 'ltrace', 'strace'],   parallel: false, estimatedSeconds: 1800 },
    { step: 5, action: 'solve',          description: 'Çözüm implementasyonu',                tools: ['python', 'custom'],          parallel: false, estimatedSeconds: 1200 },
  ],
  misc: [
    { step: 1, action: 'analyze',        description: 'Challenge analizi',                    tools: ['file', 'strings'],           parallel: false, estimatedSeconds: 300 },
    { step: 2, action: 'decode',         description: 'Encoding/obfuscation tespiti',         tools: ['base64', 'xxd'],             parallel: true,  estimatedSeconds: 600 },
    { step: 3, action: 'solve',          description: 'Çözüm',                                tools: ['python', 'custom'],          parallel: false, estimatedSeconds: 900 },
  ],
  osint: [
    { step: 1, action: 'target_id',      description: 'Hedef tanımlama',                      tools: ['whois', 'dig'],              parallel: true,  estimatedSeconds: 300 },
    { step: 2, action: 'social',         description: 'Sosyal medya istihbaratı',             tools: ['sherlock', 'theHarvester'],  parallel: true,  estimatedSeconds: 900 },
    { step: 3, action: 'domain',         description: 'Domain ve DNS istihbaratı',            tools: ['amass', 'subfinder'],        parallel: true,  estimatedSeconds: 600 },
    { step: 4, action: 'correlate',      description: 'Bilgileri ilişkilendir',               tools: ['manual'],                    parallel: false, estimatedSeconds: 1200 },
  ],
};

const DIFFICULTY_BASE_SECONDS: Record<CTFDifficulty, number> = {
  easy: 1800, medium: 3600, hard: 7200, insane: 14400, unknown: 5400,
};

const DIFFICULTY_SUCCESS: Record<CTFDifficulty, number> = {
  easy: 0.85, medium: 0.65, hard: 0.45, insane: 0.25, unknown: 0.55,
};

const FALLBACK_STRATEGIES: Record<CTFCategory, string[]> = {
  web:       ['Manuel kaynak kodu inceleme', 'Alternatif wordlist dene', 'HTTP parametre kirliliği test et'],
  crypto:    ['Bilinen düz metin saldırısı', 'Matematiksel özelliklerden yararlan', 'Yan kanal analizi'],
  pwn:       ['Alternatif exploit tekniği', 'Bilgi sızıntısı ara', 'SIGROP dene'],
  forensics: ['Alternatif forensics araçları', 'Manuel hex analizi', 'Silinmiş veri kurtarma'],
  rev:       ['Dinamik analize odaklan', 'Anti-debug bypass', 'Kütüphane analizi'],
  misc:      ['Alternatif encoding kombinasyonları', 'Metadata odaklı yaklaşım'],
  osint:     ['Alternatif kaynaklar', 'Arşiv verileri', 'Çapraz referans'],
};

export class CTFWorkflowManager {
  /** CTF challenge için workflow oluşturur */
  createWorkflow(challenge: CTFChallenge): CTFWorkflow {
    const steps = CATEGORY_STEPS[challenge.category] ?? CATEGORY_STEPS.misc;
    const baseSeconds = DIFFICULTY_BASE_SECONDS[challenge.difficulty];
    const categoryMultipliers: Record<CTFCategory, number> = {
      web: 1.0, crypto: 1.3, pwn: 1.5, forensics: 1.2, rev: 1.4, misc: 0.8, osint: 0.9,
    };
    const mult = categoryMultipliers[challenge.category] ?? 1.0;

    return {
      challenge: challenge.name,
      category: challenge.category,
      difficulty: challenge.difficulty,
      steps,
      suggestedTools: this.suggestTools(challenge),
      estimatedSeconds: Math.round(baseSeconds * mult),
      successProbability: DIFFICULTY_SUCCESS[challenge.difficulty],
      fallbackStrategies: FALLBACK_STRATEGIES[challenge.category] ?? [],
    };
  }

  /** Challenge açıklamasına göre araç önerir */
  suggestTools(challenge: CTFChallenge): string[] {
    const base = CATEGORY_TOOLS[challenge.category] ?? [];
    const desc = challenge.description.toLowerCase();
    const extra: string[] = [];

    if (challenge.category === 'web') {
      if (/sql|injection|database/.test(desc)) extra.push('sqlmap');
      if (/xss|script|javascript/.test(desc)) extra.push('dalfox');
      if (/wordpress|wp/.test(desc)) extra.push('wpscan');
      if (/jwt|token/.test(desc)) extra.push('jwt-tool');
    } else if (challenge.category === 'crypto') {
      if (/rsa|public key/.test(desc)) extra.push('rsatool', 'factordb');
      if (/hash|md5|sha/.test(desc)) extra.push('hashcat', 'john');
    } else if (challenge.category === 'pwn') {
      if (/heap|malloc/.test(desc)) extra.push('glibc-heap-analysis');
      if (/format|printf/.test(desc)) extra.push('format-string-exploiter');
    } else if (challenge.category === 'forensics') {
      if (/image|jpg|png/.test(desc)) extra.push('steghide', 'zsteg');
      if (/memory|dump/.test(desc)) extra.push('volatility');
      if (/pcap|network/.test(desc)) extra.push('wireshark');
    }

    return [...new Set([...base, ...extra])];
  }
}

export class BugBountyWorkflowManager {
  /** Subdomain keşif workflow'u */
  recon(domain: string): BugBountyWorkflow {
    return {
      domain,
      phase: 'subdomain_discovery',
      description: 'Kapsamlı subdomain ve HTTP servis keşfi',
      tools: [
        { tool: 'amass',     params: { domain, mode: 'enum' } },
        { tool: 'subfinder', params: { domain, silent: true } },
        { tool: 'httpx',     params: { probe: true, tech_detect: true, status_code: true } },
        { tool: 'katana',    params: { depth: 3, js_crawl: true } },
        { tool: 'gau',       params: { include_subs: true } },
        { tool: 'waybackurls', params: {} },
        { tool: 'paramspider', params: { level: 2 } },
        { tool: 'arjun',     params: { method: 'GET,POST', stable: true } },
      ],
      estimatedSeconds: 1320,
    };
  }

  /** Zafiyet avcılığı workflow'u */
  vulnHunting(domain: string, priorities = ['rce', 'sqli', 'xss', 'idor', 'ssrf']): BugBountyWorkflow {
    const HIGH_IMPACT: Record<string, { tools: string[]; priority: number }> = {
      rce:  { tools: ['nuclei', 'jaeles', 'sqlmap'], priority: 10 },
      sqli: { tools: ['sqlmap', 'nuclei'],           priority: 9 },
      ssrf: { tools: ['nuclei', 'ffuf'],             priority: 8 },
      idor: { tools: ['arjun', 'ffuf'],              priority: 8 },
      xss:  { tools: ['dalfox', 'nuclei'],           priority: 7 },
      lfi:  { tools: ['ffuf', 'nuclei'],             priority: 7 },
    };

    const sorted = [...priorities].sort((a, b) =>
      (HIGH_IMPACT[b]?.priority ?? 0) - (HIGH_IMPACT[a]?.priority ?? 0),
    );

    const tools = sorted.flatMap(v =>
      (HIGH_IMPACT[v]?.tools ?? []).map(tool => ({ tool, params: { target: domain } })),
    );

    return {
      domain,
      phase: 'vulnerability_hunting',
      description: `Yüksek etkili zafiyet avcılığı: ${sorted.join(', ')}`,
      tools: tools.filter((t, i, arr) => arr.findIndex(x => x.tool === t.tool) === i), // dedupe
      estimatedSeconds: sorted.length * 300,
    };
  }

  /** OSINT workflow'u */
  osint(domain: string): BugBountyWorkflow {
    return {
      domain,
      phase: 'osint',
      description: 'Açık kaynak istihbarat toplama',
      tools: [
        { tool: 'whois',        params: { domain } },
        { tool: 'dnsrecon',     params: { domain } },
        { tool: 'theHarvester', params: { domain, sources: 'all' } },
        { tool: 'shodan',       params: { query: `hostname:${domain}` } },
      ],
      estimatedSeconds: 600,
    };
  }

  /** Kimlik doğrulama bypass test workflow'u */
  authBypass(targetUrl: string, authType: 'form' | 'jwt' | 'oauth' | 'saml' = 'form'): Record<string, unknown> {
    const techniques: Record<string, string[]> = {
      form:  ["SQL Injection: admin'--", 'Varsayılan kimlik bilgileri', 'Şifre sıfırlama token yeniden kullanımı'],
      jwt:   ['Algoritma karışıklığı (RS256→HS256)', 'None algoritması', 'Anahtar karışıklığı'],
      oauth: ['Redirect URI manipülasyonu', 'State parametresi eksikliği (CSRF)', 'Yetkilendirme kodu yeniden kullanımı'],
      saml:  ['XML İmza Sarmalama', 'XXE in SAML', 'İmza doğrulama bypass'],
    };

    return {
      target: targetUrl,
      authType,
      techniques: techniques[authType] ?? [],
      estimatedSeconds: 240,
      manualRequired: true,
    };
  }
}

export const ctfManager = new CTFWorkflowManager();
export const bugBountyManager = new BugBountyWorkflowManager();

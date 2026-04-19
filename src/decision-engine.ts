/**
 * Seth Decision Engine — Hedef analizi ve akıllı tool seçimi
 * Hedef tipini belirler, en uygun araçları seçer, attack chain oluşturur.
 */

export type TargetType =
  | 'web_application'
  | 'network_host'
  | 'api_endpoint'
  | 'cloud_service'
  | 'binary_file'
  | 'unknown';

export interface TargetProfile {
  target: string;
  targetType: TargetType;
  openPorts: number[];
  technologies: string[];
  cmsType?: string;
  attackSurfaceScore: number;
  riskLevel: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
  confidenceScore: number;
}

export interface AttackStep {
  tool: string;
  params: Record<string, unknown>;
  expectedOutcome: string;
  successProbability: number;
  estimatedSeconds: number;
}

export interface AttackChain {
  target: string;
  steps: AttackStep[];
  successProbability: number;
  estimatedSeconds: number;
  riskLevel: string;
}

// Tool etkinlik puanları hedef tipine göre
const TOOL_EFFECTIVENESS: Record<string, Record<string, number>> = {
  web_application: {
    nmap: 0.8, gobuster: 0.9, nuclei: 0.95, nikto: 0.85,
    sqlmap: 0.9, ffuf: 0.9, feroxbuster: 0.85, katana: 0.88,
    httpx: 0.85, wpscan: 0.95, dalfox: 0.93, dirsearch: 0.87,
  },
  network_host: {
    nmap: 0.95, masscan: 0.92, rustscan: 0.9, enum4linux: 0.8,
    smbmap: 0.85, hydra: 0.8, netexec: 0.85, autorecon: 0.95,
  },
  api_endpoint: {
    nuclei: 0.9, ffuf: 0.85, arjun: 0.95, paramspider: 0.88,
    httpx: 0.9, x8: 0.92, katana: 0.85,
  },
  binary_file: {
    ghidra: 0.95, radare2: 0.9, gdb: 0.85, pwntools: 0.9,
    checksec: 0.75, strings: 0.7, ropper: 0.88, angr: 0.88,
  },
};

// Saldırı desenleri
const ATTACK_PATTERNS: Record<string, Array<{ tool: string; params: Record<string, unknown> }>> = {
  web_reconnaissance: [
    { tool: 'nmap',      params: { scan_type: '-sV -sC', ports: '80,443,8080,8443' } },
    { tool: 'httpx',     params: { probe: true, tech_detect: true } },
    { tool: 'katana',    params: { depth: 3, js_crawl: true } },
    { tool: 'nuclei',    params: { severity: 'critical,high', tags: 'tech' } },
    { tool: 'gobuster',  params: { mode: 'dir', extensions: 'php,html,js,txt' } },
  ],
  network_discovery: [
    { tool: 'rustscan',  params: { ulimit: 5000, scripts: true } },
    { tool: 'nmap',      params: { scan_type: '-sS -O', timing: 'T4' } },
    { tool: 'enum4linux', params: { shares: true, users: true } },
    { tool: 'smbmap',    params: { recursive: true } },
  ],
  vulnerability_assessment: [
    { tool: 'nuclei',    params: { severity: 'critical,high,medium' } },
    { tool: 'nikto',     params: { comprehensive: true } },
    { tool: 'dalfox',    params: { mining_dom: true } },
    { tool: 'sqlmap',    params: { crawl: 2, batch: true } },
  ],
  binary_exploitation: [
    { tool: 'checksec',  params: {} },
    { tool: 'ghidra',    params: { analysis_timeout: 300 } },
    { tool: 'ropper',    params: { gadget_type: 'rop' } },
    { tool: 'pwntools',  params: { exploit_type: 'local' } },
  ],
};

export class DecisionEngine {
  /** Hedefi analiz eder, profil oluşturur */
  analyzeTarget(target: string): TargetProfile {
    const targetType = this.detectTargetType(target);
    const technologies = this.detectTechnologies(target);
    const cmsType = this.detectCms(target);
    const attackSurfaceScore = this.calcAttackSurface(targetType, technologies, cmsType);
    const riskLevel = this.calcRiskLevel(attackSurfaceScore);
    const confidenceScore = this.calcConfidence(targetType, technologies, cmsType);

    return {
      target,
      targetType,
      openPorts: [],
      technologies,
      cmsType,
      attackSurfaceScore,
      riskLevel,
      confidenceScore,
    };
  }

  /** Hedefe göre en uygun araçları seçer */
  selectTools(profile: TargetProfile, objective: 'quick' | 'comprehensive' | 'stealth' = 'comprehensive'): string[] {
    const effectiveness = TOOL_EFFECTIVENESS[profile.targetType] ?? {};
    const tools = Object.keys(effectiveness);

    if (objective === 'quick') {
      return tools.sort((a, b) => (effectiveness[b] ?? 0) - (effectiveness[a] ?? 0)).slice(0, 3);
    }
    if (objective === 'stealth') {
      const stealthTools = new Set(['amass', 'subfinder', 'httpx', 'nuclei']);
      return tools.filter(t => stealthTools.has(t));
    }
    // comprehensive: etkinlik > 0.7
    const selected = tools.filter(t => (effectiveness[t] ?? 0) > 0.7);
    if (profile.cmsType?.toLowerCase() === 'wordpress' && !selected.includes('wpscan')) {
      selected.push('wpscan');
    }
    return selected;
  }

  /** Attack chain oluşturur */
  buildAttackChain(profile: TargetProfile, objective = 'comprehensive'): AttackChain {
    const patternKey = profile.targetType === 'web_application'
      ? (objective === 'quick' ? 'vulnerability_assessment' : 'web_reconnaissance')
      : profile.targetType === 'network_host'
        ? 'network_discovery'
        : profile.targetType === 'binary_file'
          ? 'binary_exploitation'
          : 'web_reconnaissance';

    const pattern = ATTACK_PATTERNS[patternKey] ?? [];
    const effectiveness = TOOL_EFFECTIVENESS[profile.targetType] ?? {};

    const steps: AttackStep[] = pattern.map(p => ({
      tool: p.tool,
      params: p.params,
      expectedOutcome: `${p.tool} ile zafiyet tespiti`,
      successProbability: (effectiveness[p.tool] ?? 0.5) * profile.confidenceScore,
      estimatedSeconds: this.estimateTime(p.tool),
    }));

    const successProbability = steps.reduce((acc, s) => acc * s.successProbability, 1);

    return {
      target: profile.target,
      steps,
      successProbability,
      estimatedSeconds: steps.reduce((acc, s) => acc + s.estimatedSeconds, 0),
      riskLevel: profile.riskLevel,
    };
  }

  private detectTargetType(target: string): TargetType {
    if (/^https?:\/\//.test(target)) {
      return target.includes('/api') ? 'api_endpoint' : 'web_application';
    }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) return 'network_host';
    if (/\.(exe|bin|elf|so|dll)$/.test(target)) return 'binary_file';
    if (/amazonaws\.com|azure|googleapis\.com/.test(target)) return 'cloud_service';
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(target)) return 'web_application';
    return 'unknown';
  }

  private detectTechnologies(target: string): string[] {
    const techs: string[] = [];
    if (/wordpress|wp-/.test(target.toLowerCase())) techs.push('wordpress');
    if (/\.php/.test(target)) techs.push('php');
    if (/\.asp/.test(target)) techs.push('dotnet');
    return techs;
  }

  private detectCms(target: string): string | undefined {
    const t = target.toLowerCase();
    if (t.includes('wordpress') || t.includes('wp-')) return 'WordPress';
    if (t.includes('drupal')) return 'Drupal';
    if (t.includes('joomla')) return 'Joomla';
    return undefined;
  }

  private calcAttackSurface(type: TargetType, techs: string[], cms?: string): number {
    const base: Record<TargetType, number> = {
      web_application: 7, api_endpoint: 6, network_host: 8,
      cloud_service: 5, binary_file: 4, unknown: 3,
    };
    let score = base[type] + techs.length * 0.5;
    if (cms) score += 1.5;
    return Math.min(score, 10);
  }

  private calcRiskLevel(score: number): TargetProfile['riskLevel'] {
    if (score >= 8) return 'critical';
    if (score >= 6) return 'high';
    if (score >= 4) return 'medium';
    if (score >= 2) return 'low';
    return 'minimal';
  }

  private calcConfidence(type: TargetType, techs: string[], cms?: string): number {
    let c = 0.5;
    if (type !== 'unknown') c += 0.1;
    if (techs.length > 0) c += 0.2;
    if (cms) c += 0.1;
    return Math.min(c, 1);
  }

  private estimateTime(tool: string): number {
    const times: Record<string, number> = {
      nmap: 120, gobuster: 300, nuclei: 180, nikto: 240,
      sqlmap: 600, ffuf: 200, hydra: 900, amass: 300,
      ghidra: 300, radare2: 180, gdb: 120, pwntools: 240,
      ropper: 120, checksec: 30, rustscan: 60, masscan: 90,
    };
    return times[tool] ?? 180;
  }
}

export const decisionEngine = new DecisionEngine();

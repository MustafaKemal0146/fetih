/**
 * Seth Parameter Optimizer — Tool parametrelerini hedefe göre otomatik optimize eder
 * Teknoloji tespiti, rate limit algılama ve profil bazlı ayarlama içerir.
 */

import type { TargetProfile } from './decision-engine.js';

export type OptimizationProfile = 'stealth' | 'normal' | 'aggressive';

export interface OptimizedParams {
  [key: string]: unknown;
  _profile?: OptimizationProfile;
  _detectedTech?: string[];
}

// Profil bazlı temel ayarlar
const PROFILE_SETTINGS: Record<string, Record<OptimizationProfile, Record<string, unknown>>> = {
  nmap: {
    stealth:     { scan_type: '-sS', timing: '-T2', additional_args: '--max-retries 1' },
    normal:      { scan_type: '-sS -sV', timing: '-T4', additional_args: '--max-retries 2' },
    aggressive:  { scan_type: '-sS -sV -sC -O', timing: '-T5', additional_args: '--min-rate 1000' },
  },
  gobuster: {
    stealth:     { threads: 5, delay: '1s', timeout: '30s' },
    normal:      { threads: 20, delay: '0s', timeout: '10s' },
    aggressive:  { threads: 50, delay: '0s', timeout: '5s' },
  },
  sqlmap: {
    stealth:     { level: 1, risk: 1, threads: 1, delay: 1 },
    normal:      { level: 2, risk: 2, threads: 5, delay: 0 },
    aggressive:  { level: 3, risk: 3, threads: 10, delay: 0 },
  },
  nuclei: {
    stealth:     { concurrency: 5, timeout: 30, rate_limit: 10 },
    normal:      { concurrency: 25, timeout: 10, rate_limit: 150 },
    aggressive:  { concurrency: 50, timeout: 5, rate_limit: 500 },
  },
  ffuf: {
    stealth:     { threads: 10, timeout: 30, rate: 10 },
    normal:      { threads: 40, timeout: 10, rate: 0 },
    aggressive:  { threads: 100, timeout: 5, rate: 0 },
  },
  feroxbuster: {
    stealth:     { threads: 5, timeout: 30 },
    normal:      { threads: 20, timeout: 10 },
    aggressive:  { threads: 50, timeout: 5 },
  },
};

// Rate limit göstergeleri
const RATE_LIMIT_PATTERNS = [
  /rate limit/i, /too many requests/i, /429/, /throttled/i,
  /slow down/i, /retry after/i, /quota exceeded/i,
];

export class ParameterOptimizer {
  /** Hedefe ve profile göre parametreleri optimize eder */
  optimize(
    tool: string,
    profile: TargetProfile,
    context: Record<string, unknown> = {},
  ): OptimizedParams {
    const optProfile = (context['profile'] as OptimizationProfile) ?? 'normal';
    const base = this.getBaseParams(tool, profile);
    const techOptimized = this.applyTechOptimizations(tool, base, profile.technologies);
    const profileOptimized = this.applyProfile(tool, techOptimized, optProfile);

    // WAF/stealth zorlaması
    if (context['stealth'] === true) {
      return this.applyProfile(tool, profileOptimized, 'stealth');
    }

    return { ...profileOptimized, _profile: optProfile, _detectedTech: profile.technologies };
  }

  /** Rate limit tespiti */
  detectRateLimit(responseText: string, statusCode: number): boolean {
    if (statusCode === 429) return true;
    return RATE_LIMIT_PATTERNS.some(p => p.test(responseText));
  }

  /** Rate limit durumunda parametreleri ayarlar */
  applyRateLimitMitigation(params: OptimizedParams): OptimizedParams {
    const adjusted = { ...params };
    if ('threads' in adjusted) adjusted['threads'] = Math.max(1, Math.floor(Number(adjusted['threads']) / 4));
    if ('rate' in adjusted) adjusted['rate'] = 10;
    adjusted['delay'] = 2;
    return adjusted;
  }

  /** Hata durumunda parametreleri ayarlar */
  adjustForError(tool: string, errorType: string, params: OptimizedParams): OptimizedParams {
    const adjusted = { ...params };
    switch (errorType) {
      case 'timeout':
        if ('threads' in adjusted) adjusted['threads'] = Math.max(1, Math.floor(Number(adjusted['threads']) / 2));
        adjusted['timeout'] = 60;
        break;
      case 'rate_limited':
        return this.applyRateLimitMitigation(adjusted);
      case 'resource_exhausted':
        if ('threads' in adjusted) adjusted['threads'] = 3;
        if ('batch_size' in adjusted) adjusted['batch_size'] = Math.floor(Number(adjusted['batch_size']) * 0.5);
        break;
    }
    return adjusted;
  }

  private getBaseParams(tool: string, profile: TargetProfile): Record<string, unknown> {
    const base: Record<string, unknown> = { target: profile.target };

    switch (tool) {
      case 'nmap':
        base['ports'] = profile.targetType === 'web_application' ? '80,443,8080,8443' : '1-1000';
        break;
      case 'gobuster':
        base['mode'] = 'dir';
        base['wordlist'] = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt';
        break;
      case 'sqlmap':
        base['batch'] = true;
        break;
      case 'nuclei':
        base['severity'] = 'critical,high,medium';
        break;
    }
    return base;
  }

  private applyTechOptimizations(
    tool: string,
    params: Record<string, unknown>,
    technologies: string[],
  ): Record<string, unknown> {
    const optimized = { ...params };

    if (technologies.includes('wordpress')) {
      if (tool === 'gobuster') optimized['extensions'] = 'php,html,txt,xml';
      if (tool === 'nuclei') optimized['tags'] = 'wordpress';
    }
    if (technologies.includes('php')) {
      if (tool === 'gobuster') optimized['extensions'] = 'php,php3,php4,php5,phtml,html';
      if (tool === 'sqlmap') optimized['dbms'] = 'mysql';
    }
    if (technologies.includes('dotnet')) {
      if (tool === 'gobuster') optimized['extensions'] = 'aspx,asp,html,txt';
      if (tool === 'sqlmap') optimized['dbms'] = 'mssql';
    }

    return optimized;
  }

  private applyProfile(
    tool: string,
    params: Record<string, unknown>,
    profile: OptimizationProfile,
  ): Record<string, unknown> {
    const profileSettings = PROFILE_SETTINGS[tool]?.[profile];
    if (!profileSettings) return params;
    return { ...params, ...profileSettings };
  }
}

export const parameterOptimizer = new ParameterOptimizer();

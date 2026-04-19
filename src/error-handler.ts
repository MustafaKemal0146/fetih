/**
 * Seth Error Handler — Akıllı hata sınıflandırma ve otomatik kurtarma
 * Hata tipini tespit eder, en uygun recovery stratejisini seçer.
 */

export type ErrorType =
  | 'timeout'
  | 'permission_denied'
  | 'network_unreachable'
  | 'rate_limited'
  | 'tool_not_found'
  | 'invalid_parameters'
  | 'resource_exhausted'
  | 'authentication_failed'
  | 'target_unreachable'
  | 'parsing_error'
  | 'unknown';

export type RecoveryAction =
  | 'retry_with_backoff'
  | 'retry_with_reduced_scope'
  | 'switch_to_alternative'
  | 'adjust_parameters'
  | 'graceful_degradation'
  | 'abort';

export interface RecoveryStrategy {
  action: RecoveryAction;
  params: Record<string, unknown>;
  maxAttempts: number;
  backoffMultiplier: number;
  successProbability: number;
  estimatedSeconds: number;
}

export interface ErrorContext {
  toolName: string;
  target: string;
  errorType: ErrorType;
  errorMessage: string;
  attemptCount: number;
}

// Hata deseni → tip eşlemesi
const ERROR_PATTERNS: Array<[RegExp, ErrorType]> = [
  [/timeout|timed out|connection timeout/i,          'timeout'],
  [/permission denied|access denied|forbidden/i,     'permission_denied'],
  [/network unreachable|host unreachable|no route/i, 'network_unreachable'],
  [/rate limit|too many requests|429|throttled/i,    'rate_limited'],
  [/command not found|no such file|not found/i,      'tool_not_found'],
  [/invalid argument|invalid option|syntax error/i,  'invalid_parameters'],
  [/out of memory|disk full|no space left/i,         'resource_exhausted'],
  [/authentication failed|unauthorized|invalid token/i, 'authentication_failed'],
  [/target unreachable|host not found|dns resolution/i, 'target_unreachable'],
  [/parse error|invalid format|malformed|json decode/i, 'parsing_error'],
];

// Her hata tipi için recovery stratejileri
const RECOVERY_STRATEGIES: Record<ErrorType, RecoveryStrategy[]> = {
  timeout: [
    { action: 'retry_with_backoff',       params: { initialDelay: 5, maxDelay: 60 },  maxAttempts: 3, backoffMultiplier: 2.0, successProbability: 0.7, estimatedSeconds: 30 },
    { action: 'retry_with_reduced_scope', params: { reduceThreads: true },             maxAttempts: 2, backoffMultiplier: 1.0, successProbability: 0.8, estimatedSeconds: 45 },
    { action: 'switch_to_alternative',    params: { preferFaster: true },              maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 0.6, estimatedSeconds: 60 },
  ],
  permission_denied: [
    { action: 'switch_to_alternative',    params: { noPrivileges: true },              maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 0.5, estimatedSeconds: 30 },
    { action: 'abort',                    params: { reason: 'privilege_required' },    maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 0.9, estimatedSeconds: 0 },
  ],
  network_unreachable: [
    { action: 'retry_with_backoff',       params: { initialDelay: 10, maxDelay: 120 }, maxAttempts: 3, backoffMultiplier: 2.0, successProbability: 0.6, estimatedSeconds: 60 },
    { action: 'graceful_degradation',     params: { skipTarget: true },                maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 1.0, estimatedSeconds: 5 },
  ],
  rate_limited: [
    { action: 'retry_with_backoff',       params: { initialDelay: 30, maxDelay: 300 }, maxAttempts: 5, backoffMultiplier: 1.5, successProbability: 0.9, estimatedSeconds: 180 },
    { action: 'adjust_parameters',        params: { reduceRate: true },                maxAttempts: 2, backoffMultiplier: 1.0, successProbability: 0.8, estimatedSeconds: 120 },
  ],
  tool_not_found: [
    { action: 'switch_to_alternative',    params: { findEquivalent: true },            maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 0.7, estimatedSeconds: 15 },
    { action: 'abort',                    params: { reason: 'tool_missing' },          maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 1.0, estimatedSeconds: 0 },
  ],
  invalid_parameters: [
    { action: 'adjust_parameters',        params: { useDefaults: true },               maxAttempts: 3, backoffMultiplier: 1.0, successProbability: 0.8, estimatedSeconds: 10 },
    { action: 'switch_to_alternative',    params: { simplerInterface: true },          maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 0.6, estimatedSeconds: 30 },
  ],
  resource_exhausted: [
    { action: 'retry_with_reduced_scope', params: { reduceMemory: true },              maxAttempts: 2, backoffMultiplier: 1.0, successProbability: 0.7, estimatedSeconds: 60 },
    { action: 'retry_with_backoff',       params: { initialDelay: 60, maxDelay: 300 }, maxAttempts: 2, backoffMultiplier: 2.0, successProbability: 0.5, estimatedSeconds: 180 },
  ],
  authentication_failed: [
    { action: 'abort',                    params: { reason: 'auth_required' },         maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 0.9, estimatedSeconds: 0 },
  ],
  target_unreachable: [
    { action: 'retry_with_backoff',       params: { initialDelay: 15, maxDelay: 180 }, maxAttempts: 3, backoffMultiplier: 2.0, successProbability: 0.6, estimatedSeconds: 90 },
    { action: 'graceful_degradation',     params: { skipTarget: true },                maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 1.0, estimatedSeconds: 5 },
  ],
  parsing_error: [
    { action: 'adjust_parameters',        params: { changeOutputFormat: true },        maxAttempts: 2, backoffMultiplier: 1.0, successProbability: 0.7, estimatedSeconds: 20 },
    { action: 'switch_to_alternative',    params: { betterOutput: true },              maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 0.6, estimatedSeconds: 30 },
  ],
  unknown: [
    { action: 'retry_with_backoff',       params: { initialDelay: 5, maxDelay: 30 },   maxAttempts: 2, backoffMultiplier: 2.0, successProbability: 0.3, estimatedSeconds: 45 },
    { action: 'abort',                    params: { reason: 'unknown_error' },         maxAttempts: 1, backoffMultiplier: 1.0, successProbability: 0.9, estimatedSeconds: 0 },
  ],
};

// Tool alternatifleri
const TOOL_ALTERNATIVES: Record<string, string[]> = {
  nmap:        ['rustscan', 'masscan'],
  gobuster:    ['feroxbuster', 'dirsearch', 'ffuf'],
  nuclei:      ['nikto', 'jaeles'],
  sqlmap:      ['sqlninja'],
  ffuf:        ['gobuster', 'feroxbuster', 'wfuzz'],
  subfinder:   ['amass', 'assetfinder'],
  amass:       ['subfinder', 'assetfinder'],
  ghidra:      ['radare2'],
  radare2:     ['ghidra', 'objdump'],
  hashcat:     ['john'],
  john:        ['hashcat'],
};

export class ErrorHandler {
  private errorHistory: ErrorContext[] = [];

  /** Hata mesajından tip tespit eder */
  classify(errorMessage: string, exception?: Error): ErrorType {
    if (exception instanceof TypeError) return 'invalid_parameters';
    if (exception?.message?.includes('ENOENT')) return 'tool_not_found';
    if (exception?.message?.includes('ECONNREFUSED')) return 'network_unreachable';

    for (const [pattern, type] of ERROR_PATTERNS) {
      if (pattern.test(errorMessage)) return type;
    }
    return 'unknown';
  }

  /** En iyi recovery stratejisini seçer */
  getRecovery(ctx: ErrorContext): RecoveryStrategy {
    this.errorHistory.push(ctx);
    const strategies = RECOVERY_STRATEGIES[ctx.errorType] ?? RECOVERY_STRATEGIES.unknown;
    const viable = strategies.filter(s => ctx.attemptCount <= s.maxAttempts);

    if (viable.length === 0) {
      return { action: 'abort', params: { reason: 'all_strategies_exhausted' }, maxAttempts: 1, backoffMultiplier: 1, successProbability: 1, estimatedSeconds: 0 };
    }

    // En yüksek başarı olasılığı × en az süre
    return viable.sort((a, b) => {
      const scoreA = a.successProbability - a.estimatedSeconds / 1000;
      const scoreB = b.successProbability - b.estimatedSeconds / 1000;
      return scoreB - scoreA;
    })[0]!;
  }

  /** Alternatif tool önerir */
  getAlternative(failedTool: string): string | undefined {
    return TOOL_ALTERNATIVES[failedTool]?.[0];
  }

  /** Parametreleri hata tipine göre otomatik ayarlar */
  adjustParams(tool: string, errorType: ErrorType, params: Record<string, unknown>): Record<string, unknown> {
    const adjusted = { ...params };
    if (errorType === 'timeout') {
      if ('threads' in adjusted) adjusted['threads'] = Math.max(1, Math.floor(Number(adjusted['threads']) / 2));
      adjusted['timeout'] = 60;
    } else if (errorType === 'rate_limited') {
      if ('threads' in adjusted) adjusted['threads'] = Math.max(1, Math.floor(Number(adjusted['threads']) / 4));
      adjusted['delay'] = 2;
    } else if (errorType === 'resource_exhausted') {
      if ('threads' in adjusted) adjusted['threads'] = 3;
    }
    return adjusted;
  }

  /** Hata istatistiklerini döner */
  getStats(): Record<string, unknown> {
    const counts: Record<string, number> = {};
    for (const e of this.errorHistory) {
      counts[e.errorType] = (counts[e.errorType] ?? 0) + 1;
    }
    return { total: this.errorHistory.length, byType: counts };
  }
}

export const errorHandler = new ErrorHandler();

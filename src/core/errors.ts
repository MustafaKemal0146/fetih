/**
 * @fileoverview FETIH — Özel hata hiyerarşisi.
 */

export class FetihError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'FetihError';
  }
}

export class ProviderError extends FetihError {
  constructor(
    message: string,
    public readonly provider: string,
    public readonly statusCode?: number,
  ) {
    super(message, 'PROVIDER_ERROR');
    this.name = 'ProviderError';
  }
}

export class ToolExecutionError extends FetihError {
  constructor(
    message: string,
    public readonly toolName: string,
  ) {
    super(message, 'TOOL_EXECUTION_ERROR');
    this.name = 'ToolExecutionError';
  }
}

export class PermissionDeniedError extends FetihError {
  constructor(
    message: string,
    public readonly toolName: string,
  ) {
    super(message, 'PERMISSION_DENIED');
    this.name = 'PermissionDeniedError';
  }
}

export class BudgetExceededError extends FetihError {
  constructor(message: string) {
    super(message, 'BUDGET_EXCEEDED');
    this.name = 'BudgetExceededError';
  }
}

export class ConfigError extends FetihError {
  constructor(message: string) {
    super(message, 'CONFIG_ERROR');
    this.name = 'ConfigError';
  }
}

export class AbortError extends FetihError {
  constructor() {
    super('İşlem kullanıcı tarafından iptal edildi', 'ABORT');
    this.name = 'AbortError';
  }
}

import { describe, it, expect } from 'vitest';
import { getModelPrice } from '../src/model-cost.js';

describe('getModelPrice', () => {
  it('should return exact match when available', () => {
    // We know 'gpt-4o' is exactly matched and has { input: 5.00, output: 15.00 }
    const result = getModelPrice('gpt-4o', 'openai');
    expect(result).toEqual({ input: 5.00, output: 15.00 });
  });

  it('should return prefix match when model starts with key', () => {
    // 'claude-3-5-sonnet-latest' has a price. If we ask for 'claude-3-5-sonnet-latest-123'
    // it starts with 'claude-3-5-sonnet-latest'
    const result = getModelPrice('claude-3-5-sonnet-latest-123', 'anthropic');
    expect(result).toEqual({ input: 3.00, output: 15.00 });
  });

  it('should return prefix match when key starts with model', () => {
    // If we ask for 'claude-3-5-sonnet', the key 'claude-3-5-sonnet-latest' starts with 'claude-3-5-sonnet'
    const result = getModelPrice('claude-3-5-sonnet', 'anthropic');
    expect(result).toEqual({ input: 3.00, output: 15.00 });
  });

  it('should fallback to provider default when no match is found', () => {
    // Provider openai has default { input: 5.00, output: 15.00 }
    const result = getModelPrice('unknown-gpt-model', 'openai');
    expect(result).toEqual({ input: 5.00, output: 15.00 });

    // Provider ollama has default { input: 0, output: 0 }
    const resultOllama = getModelPrice('llama3', 'ollama');
    expect(resultOllama).toEqual({ input: 0, output: 0 });
  });

  it('should fallback to absolute default when neither model nor provider match', () => {
    // Absolute default is { input: 3.00, output: 15.00 }
    const result = getModelPrice('unknown-model', 'unknown-provider');
    expect(result).toEqual({ input: 3.00, output: 15.00 });
  });
});

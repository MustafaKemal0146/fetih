/**
 * @fileoverview LLM Provider interface and factory.
 * Clean-room implementation — provider-agnostic abstraction layer.
 */

import type { LLMProvider, ProviderName, FetihConfig } from '../types.js';
import { ProviderError } from '../core/errors.js';
import { resolveProviderApiKey } from '../config/settings.js';

/** Geriye dönük uyumluluk alias'ları. */
const ALIAS: Record<string, ProviderName> = {
  claude: 'anthropic',
  gemini: 'google',
};

function resolveName(name: ProviderName): ProviderName {
  return (ALIAS[name as string] ?? name) as ProviderName;
}

/**
 * Create an LLM provider instance by name.
 * Uses lazy imports to avoid loading unused SDKs.
 */
export async function createProvider(
  name: ProviderName,
  config: FetihConfig,
): Promise<LLMProvider> {
  const resolved = resolveName(name);
  const errPrefix = resolved === 'anthropic' ? 'anthropic' : resolved === 'google' ? 'google' : resolved;

  switch (resolved) {
    case 'anthropic': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('ANTHROPIC_API_KEY is not set.', resolved);
      const { AnthropicProvider } = await import('./anthropic.js');
      return new AnthropicProvider(apiKey);
    }
    case 'openai': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('OPENAI_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey);
    }
    case 'google': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('GEMINI_API_KEY is not set.', resolved);
      const { GoogleProvider } = await import('./google.js');
      return new GoogleProvider(apiKey);
    }
    case 'ollama': {
      const baseUrl = config.providers.ollama?.baseUrl ?? 'http://localhost:11434';
      const { OllamaProvider } = await import('./ollama.js');
      return new OllamaProvider(baseUrl);
    }
    case 'openrouter': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('OPENROUTER_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://openrouter.ai/api/v1');
    }
    case 'groq': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('GROQ_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://api.groq.com/openai/v1');
    }
    case 'mistral': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('MISTRAL_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://api.mistral.ai/v1');
    }
    case 'deepseek': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('DEEPSEEK_API_KEY is not set.', resolved);
      const { DeepSeekProvider } = await import('./deepseek.js');
      return new DeepSeekProvider(apiKey);
    }
    case 'xai': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('XAI_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://api.x.ai/v1');
    }
    case 'lmstudio': {
      const baseUrl = config.providers.lmstudio?.baseUrl ?? 'http://localhost:1234';
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider('lm-studio', `${baseUrl}/v1`);
    }
    case 'litellm': {
      const baseUrl = config.providers.litellm?.baseUrl ?? 'http://localhost:4000';
      const apiKey = resolveProviderApiKey(resolved, config) ?? 'litellm';
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, `${baseUrl}/v1`);
    }
    case 'github-copilot': {
      const baseUrl = config.providers['github-copilot']?.baseUrl ?? 'http://localhost:3000';
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider('n/a', `${baseUrl}/v1`);
    }
    // === OpenAI uyumlu yeni provider'lar ===
    case 'fireworks': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('FIREWORKS_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://api.fireworks.ai/inference/v1');
    }
    case 'together': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('TOGETHER_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://api.together.xyz/v1');
    }
    case 'perplexity': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('PERPLEXITY_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://api.perplexity.ai');
    }
    case 'huggingface': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('HF_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://api-inference.huggingface.co/v1');
    }
    case 'nvidia': {
      const apiKey = resolveProviderApiKey(resolved, config);
      if (!apiKey) throw new ProviderError('NVIDIA_API_KEY is not set.', resolved);
      const { OpenAIProvider } = await import('./openai.js');
      return new OpenAIProvider(apiKey, 'https://integrate.api.nvidia.com/v1');
    }
    default: {
      throw new ProviderError(`Unknown provider: ${name as string}`, name as string);
    }
  }
}

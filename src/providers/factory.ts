import type { ProviderName, ProviderConfig } from '../types.js';

export async function listModels(name: ProviderName, config?: ProviderConfig): Promise<string[]> {
  switch (name) {
    case 'ollama': {
      const { OllamaProvider } = await import('./ollama.js');
      const provider = new OllamaProvider(config?.baseUrl ?? 'http://localhost:11434');
      return provider.listModels();
    }
    case 'openai':
    case 'groq':
    case 'deepseek':
    case 'mistral':
    case 'xai':
    case 'openrouter': {
      // Basic list for common providers
      return ['default-model'];
    }
    default:
      return [];
  }
}

/**
 * Settings view — provider, model, güvenlik ayarları, API anahtarları
 */
import { state } from '../state.js';
import { wsSend, onWsEvent } from '../ws.js';

export function initializeSettingsView() {
  const providerSel = document.getElementById('sel-provider');
  const modelSel = document.getElementById('sel-model');
  const effortSel = document.getElementById('sel-effort');
  const permissionSel = document.getElementById('sel-permission');
  const securitySel = document.getElementById('sel-security');
  const feedback = document.getElementById('api-key-feedback');

  // Load available models
  document.querySelector('[data-view="settings"]')?.addEventListener('click', () => {
    wsSend('get_models', providerSel?.value ?? 'openai');
  }, { once: true });

  if (providerSel) {
    // FETIH'in desteklediği provider'lar — tam liste
    const providers = ['deepseek', 'anthropic', 'google', 'openai', 'ollama', 'nvidia'];
    providers.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p;
      opt.textContent = p.charAt(0).toUpperCase() + p.slice(1);
      providerSel.appendChild(opt);
    });

    providerSel.addEventListener('change', () => {
      wsSend('get_models', providerSel.value);
    });
  }

  if (effortSel) {
    effortSel.addEventListener('change', () => {
      wsSend('command', `/effort ${effortSel.value}`);
    });

    // Sync from state
    Object.defineProperty(state, 'effort', {
      set(val) {
        if (effortSel) effortSel.value = val;
      },
      configurable: true,
    });
  }

  if (permissionSel) {
    permissionSel.addEventListener('change', () => {
      wsSend('command', `/permission ${permissionSel.value}`);
    });
  }

  if (securitySel) {
    securitySel.addEventListener('change', () => {
      wsSend('command', `/security ${securitySel.value}`);
    });
  }

  // Handle models response
  onWsEvent('models', (data) => {
    if (!modelSel || !data?.models) return;
    modelSel.innerHTML = '';
    data.models.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m;
      opt.textContent = m;
      modelSel.appendChild(opt);
    });
  });

  // ── API Key Management ──────────────────────────────────

  // Request current API key status when settings view opens
  document.querySelector('[data-view="settings"]')?.addEventListener('click', () => {
    wsSend('get_api_keys', {});
  }, { once: true });

  // Also request on every settings view visit
  document.querySelector('[data-view="settings"]')?.addEventListener('click', () => {
    wsSend('get_api_keys', {});
  });

  // Handle API key status response
  onWsEvent('api_key_status', (data) => {
    if (!data?.keys) return;
    for (const [provider, info] of Object.entries(data.keys)) {
      const input = document.getElementById(`api-key-${provider}`);
      if (!input) continue;
      if (info.hasKey) {
        input.placeholder = '•••••••••••••••• (kayıtlı)';
        input.classList.add('saved');
      } else {
        input.placeholder = 'API anahtarı gir...';
        input.classList.remove('saved');
      }
    }
    if (feedback) {
      feedback.textContent = '✅ API anahtarı durumları güncellendi';
      feedback.className = 'api-key-feedback success';
      setTimeout(() => { feedback.textContent = ''; feedback.className = 'api-key-feedback'; }, 3000);
    }
  });

  // Toggle password visibility
  document.querySelectorAll('.toggle-vis').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const input = document.getElementById(targetId);
      if (!input) return;
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🙈';
      } else {
        input.type = 'password';
        btn.textContent = '👁';
      }
    });
  });

  // Save API key
  document.querySelectorAll('.btn-save-key').forEach(btn => {
    btn.addEventListener('click', () => {
      const provider = btn.dataset.provider;
      const input = document.getElementById(`api-key-${provider}`);
      if (!input) return;
      const key = input.value.trim();
      if (!key) {
        if (feedback) {
          feedback.textContent = '❌ Lütfen bir API anahtarı gir';
          feedback.className = 'api-key-feedback error';
          setTimeout(() => { feedback.textContent = ''; feedback.className = 'api-key-feedback'; }, 3000);
        }
        return;
      }

      // Send to server via websocket
      wsSend('set_api_key', { provider, apiKey: key });

      // Visual feedback
      input.classList.add('saved');
      input.value = '';
      input.placeholder = '•••••••••••••••• (kaydedildi)';
      input.type = 'password';

      if (feedback) {
        feedback.textContent = `✅ ${provider} API anahtarı kaydedildi`;
        feedback.className = 'api-key-feedback success';
        setTimeout(() => { feedback.textContent = ''; feedback.className = 'api-key-feedback'; }, 3000);
      }
    });
  });

  // Handle save confirmation from server
  onWsEvent('api_key_saved', (data) => {
    if (!data?.provider) return;
    const input = document.getElementById(`api-key-${data.provider}`);
    if (input) {
      input.classList.add('saved');
    }
    if (feedback) {
      feedback.textContent = `✅ ${data.provider} API anahtarı başarıyla kaydedildi`;
      feedback.className = 'api-key-feedback success';
      setTimeout(() => { feedback.textContent = ''; feedback.className = 'api-key-feedback'; }, 3000);
    }
  });

  onWsEvent('api_key_error', (data) => {
    if (!data?.provider) return;
    if (feedback) {
      feedback.textContent = `❌ ${data.provider}: ${data.error || 'Kaydedilemedi'}`;
      feedback.className = 'api-key-feedback error';
      setTimeout(() => { feedback.textContent = ''; feedback.className = 'api-key-feedback'; }, 3000);
    }
  });
}

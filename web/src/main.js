/**
 * SETH Web UI — Main Entry Point
 * Vite-based modular application.
 */

import { state, on } from './state.js';
import { connectWs, onWsEvent, wsSend } from './ws.js';
import { fetchStatus, fetchStats, fetchSessions } from './api.js';
import { initializeChatView, renderChatMessage } from './views/chat.js';
import { initializeDashboardView } from './views/dashboard.js';
import { initializeSettingsView } from './views/settings.js';
import { initializeLogsView, addLogEntry } from './views/logs.js';
import { escapeHtml, scrollToBottom, formatUptime } from './utils.js';
import { updateStatusBar } from './components/status-bar.js';

import './styles/main.css';
import './styles/chat.css';
import './styles/dashboard.css';
import './styles/components.css';

document.addEventListener('DOMContentLoaded', () => {
  init();
});

async function init() {
  // Navigation
  initNavigation();

  // Initialize views
  initializeChatView();
  initializeDashboardView();
  initializeSettingsView();
  initializeLogsView();

  // Connect WebSocket
  connectWs();

  // State listeners
  on('connected', () => updateConnectionStatus(true));
  on('disconnected', () => updateConnectionStatus(false));
  on('processing', (val) => updateProcessingState(val));
  on('stats', (stats) => {
    if (stats) updateStatsUI(stats);
  });
  on('daemonStatus', (status) => {
    if (status) updateDaemonUI(status);
  });
  on('messages', () => {
    // Chat view handles its own rendering
  });

  // WebSocket events
  onWsEvent('init', (data) => {
    if (data.history) {
      state.messages = data.history;
      data.history.forEach(msg => renderChatMessage(msg));
    }
    if (data.stats) {
      state.stats = data.stats;
      updateStatsUI(data.stats);
    }
    if (data.settings) {
      Object.assign(state.settings, data.settings);
    }
    // API anahtarı durumlarını settings view'e bildir
    if (data.apiKeys) {
      state.apiKeys = data.apiKeys;
      // settings view zaten init edilmişse input placeholder'ları güncellenir
      Object.entries(data.apiKeys).forEach(([provider, info]) => {
        const input = document.getElementById(`api-key-${provider}`);
        if (!input) return;
        if (info.hasKey) {
          input.placeholder = '•••••••••••••••• (kayıtlı)';
          input.classList.add('saved');
        }
      });
    }
  });

  onWsEvent('text', (text) => {
    appendToLastMessage(text);
  });

  onWsEvent('tool_call', (data) => {
    addToolCallCard(data);
  });

  onWsEvent('tool_result', (data) => {
    updateToolResult(data);
  });

  onWsEvent('status', (data) => {
    state.processing = data.processing;
    updateStatusBar(data);
  });

  onWsEvent('stats', (data) => {
    state.stats = data;
    updateStatsUI(data);
  });

  onWsEvent('history', (messages) => {
    state.messages = messages;
    document.getElementById('chat-messages').innerHTML = '';
    messages.forEach(msg => renderChatMessage(msg));
  });

  onWsEvent('daemon_status', (data) => {
    state.daemonStatus = data;
    updateDaemonUI(data);
  });

  onWsEvent('daemon_log', (data) => {
    addLogEntry(data);
  });

  onWsEvent('warning', (data) => {
    showWarning(data.message);
  });

  // Initial data fetch
  try {
    const status = await fetchStatus();
    state.daemonStatus = status;
    updateDaemonUI(status);
  } catch {}
  try {
    const stats = await fetchStats();
    state.stats = stats;
    updateStatsUI(stats);
  } catch {}
  try {
    const sessionData = await fetchSessions();
    updateSessionCount(sessionData.count ?? 0);
  } catch {}

  // Request daemon status via WebSocket too
  wsSend('daemon_status_request', {});
}

function initNavigation() {
  document.querySelectorAll('[data-view]').forEach(btn => {
    btn.addEventListener('click', () => {
      const viewName = btn.dataset.view;
      switchView(viewName);
    });
  });
}

function switchView(name) {
  // Update nav
  document.querySelectorAll('[data-view]').forEach(b => b.classList.remove('active'));
  document.querySelector(`[data-view="${name}"]`)?.classList.add('active');

  // Show view
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(`view-${name}`)?.classList.add('active');

  state.currentView = name;
}

function updateConnectionStatus(connected) {
  const el = document.getElementById('conn-status');
  if (!el) return;
  const dot = el.querySelector('.status-dot');
  const label = el.querySelector('.status-label');
  if (connected) {
    dot.className = 'status-dot online';
    label.textContent = 'Bağlı';
  } else {
    dot.className = 'status-dot offline';
    label.textContent = 'Bağlantı kesik';
  }
}

function updateProcessingState(processing) {
  const btn = document.getElementById('btn-send');
  if (btn) btn.disabled = processing;
}

function updateStatsUI(stats) {
  setText('s-provider', stats.provider ?? '—');
  setText('s-model', stats.model ?? '—');
  setText('s-messages', String(stats.messages ?? 0));
  setText('s-input-tokens', String(stats.inputTokens ?? 0));
  setText('s-output-tokens', String(stats.outputTokens ?? 0));
  setText('s-turns', String(stats.turns ?? 0));
  setText('model-badge', stats.model ? `${stats.provider ?? ''} ${stats.model}` : 'AI Agent');
}

function updateDaemonUI(status) {
  if (!status) return;
  const statusEl = document.getElementById('d-status');
  if (status.running) {
    statusEl.className = 'badge badge-green';
    statusEl.textContent = 'Çalışıyor';
  } else {
    statusEl.className = 'badge badge-red';
    statusEl.textContent = 'Durdu';
  }
  setText('d-pid', String(status.pid ?? '—'));
  setText('d-port', String(status.port ?? '—'));
  setText('d-uptime', status.uptime != null ? formatUptime(status.uptime) : '—');
  setText('d-sessions', String(status.sessions ?? 0));
  const started = status.startedAt ? new Date(status.startedAt).toLocaleString('tr-TR') : '—';

  // Update session count
  updateSessionCount(status.sessions ?? 0);
}

function updateSessionCount(count) {
  setText('s-sessions', String(count));
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// formatTime için utils.js'deki formatUptime kullanılıyor

function appendToLastMessage(text) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  let lastMsg = container.querySelector('.message:last-child');
  if (!lastMsg || lastMsg.dataset.role !== 'assistant') {
    const wrapper = document.createElement('div');
    wrapper.className = 'message assistant streaming';
    wrapper.dataset.role = 'assistant';
    wrapper.innerHTML = '<div class="message-content"><div class="message-bubble"><div class="streaming-content"></div><span class="cursor-blink">▊</span></div></div>';
    container.appendChild(wrapper);
    lastMsg = wrapper;
  }
  const content = lastMsg.querySelector('.streaming-content');
  if (content) {
    content.textContent += text;
    scrollToBottom(container);
  }
}

function addToolCallCard(data) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const card = document.createElement('div');
  card.className = 'tool-card';
  card.dataset.toolName = data.name;
  card.innerHTML = `
    <div class="tool-card-header" onclick="this.parentElement.classList.toggle('collapsed')">
      <span class="tool-card-icon">🔧</span>
      <span class="tool-card-name">${escapeHtml(data.name)}</span>
      <span class="tool-card-toggle">▼</span>
    </div>
    <div class="tool-card-body">
      <pre class="tool-card-input">${escapeHtml(JSON.stringify(data.input, null, 2))}</pre>
      <div class="tool-card-result" style="display:none"></div>
    </div>
  `;
  container.appendChild(card);
  scrollToBottom(container);
}

function updateToolResult(data) {
  const cards = document.querySelectorAll('.tool-card');
  const card = Array.from(cards).find(c => c.dataset.toolName === data.name);
  if (!card) return;
  card.classList.remove('collapsed');
  const resultEl = card.querySelector('.tool-card-result');
  if (resultEl) {
    resultEl.textContent = data.isError ? `❌ ${data.output}` : `✅ ${data.output}`;
    resultEl.className = `tool-card-result ${data.isError ? 'error' : 'success'}`;
    resultEl.style.display = 'block';
  }
}

function showWarning(message) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const warn = document.createElement('div');
  warn.className = 'warning-banner';
  warn.innerHTML = `⚠️ ${escapeHtml(message)}`;
  container.appendChild(warn);
  scrollToBottom(container);
}

// escapeHtml ve scrollToBottom utils.js'den import ediliyor

// Global functions for inline onclick handlers
window.addToolCallCard = addToolCallCard;
window.updateToolResult = updateToolResult;

/**
 * Dashboard view — istatistikler ve daemon durumu
 */
import { state, on } from '../state.js';
import { fetchStatus, fetchStats } from '../api.js';
import { formatUptime, formatNumber } from '../utils.js';

export function initializeDashboardView() {
  // Periodic refresh
  let refreshTimer;

  on('daemonStatus', updateCard);
  on('stats', updateStatsCard);

  // Refresh when view becomes active
  on('currentView', (view) => {
    if (view === 'dashboard') {
      refreshNow();
      refreshTimer = setInterval(refreshNow, 5000);
    } else {
      clearInterval(refreshTimer);
    }
  });
}

async function refreshNow() {
  try {
    const status = await fetchStatus();
    state.daemonStatus = status;
    updateCard(status);
  } catch {}
  try {
    const stats = await fetchStats();
    state.stats = stats;
    updateStatsCard(stats);
  } catch {}
}

function updateCard(status) {
  if (!status) return;
  const dStatus = document.getElementById('d-status');
  if (dStatus) {
    dStatus.textContent = status.running ? 'Çalışıyor' : 'Durdu';
    dStatus.className = `badge ${status.running ? 'badge-green' : 'badge-red'}`;
  }
  setText('d-pid', status.pid != null ? String(status.pid) : '—');
  setText('d-port', status.port != null ? String(status.port) : '—');
  setText('d-uptime', formatUptime(status.uptime));
  setText('d-sessions', String(status.sessions ?? 0));
}

function updateStatsCard(stats) {
  if (!stats) return;
  setText('s-provider', stats.provider ?? '—');
  setText('s-model', stats.model ?? '—');
  setText('s-messages', formatNumber(stats.messages));
  setText('s-input-tokens', formatNumber(stats.inputTokens));
  setText('s-output-tokens', formatNumber(stats.outputTokens));
  setText('s-turns', formatNumber(stats.turns));
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

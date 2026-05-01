/**
 * Logs view — daemon log akışı
 */
import { onWsEvent } from '../ws.js';

let logOutput;
let logFilter = 'ALL';
let logEntries = [];

export function initializeLogsView() {
  logOutput = document.getElementById('log-output');
  const filterEl = document.getElementById('log-level-filter');
  const clearBtn = document.getElementById('btn-clear-logs');

  if (filterEl) {
    filterEl.addEventListener('change', () => {
      logFilter = filterEl.value;
      renderLogs();
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      logEntries = [];
      renderLogs();
    });
  }

  // Listen for daemon_log events via WebSocket
  onWsEvent('daemon_log', (data) => {
    addLogEntry(data);
  });
}

export function addLogEntry(data) {
  // data: { level: 'INFO'|'WARN'|'ERROR'|'DEBUG', timestamp: string, message: string }
  if (!data) return;

  const entry = {
    level: data.level || 'INFO',
    timestamp: data.timestamp || new Date().toISOString(),
    message: data.message || String(data),
  };

  logEntries.push(entry);
  if (logEntries.length > 1000) logEntries.shift(); // keep last 1000

  // Only render if visible and matching filter
  const view = document.getElementById('view-logs');
  if (view?.classList.contains('active')) {
    if (logFilter === 'ALL' || logFilter === entry.level) {
      appendLogLine(entry);
    }
  }
}

function renderLogs() {
  if (!logOutput) return;

  const filtered = logFilter === 'ALL'
    ? logEntries
    : logEntries.filter(e => e.level === logFilter);

  logOutput.innerHTML = filtered.length === 0
    ? '<span class="log-placeholder">Log bulunamadı.</span>'
    : filtered.map(formatLogLine).join('\n');

  logOutput.scrollTop = logOutput.scrollHeight;
}

function appendLogLine(entry) {
  if (!logOutput) return;

  // Remove placeholder if present
  const placeholder = logOutput.querySelector('.log-placeholder');
  if (placeholder) logOutput.innerHTML = '';

  const line = document.createElement('div');
  line.className = `log-line log-${entry.level.toLowerCase()}`;
  line.textContent = formatLogLine(entry);
  logOutput.appendChild(line);
  logOutput.scrollTop = logOutput.scrollHeight;
}

function formatLogLine(entry) {
  const time = new Date(entry.timestamp).toLocaleTimeString('tr-TR');
  return `[${time}] [${entry.level}] ${entry.message}`;
}

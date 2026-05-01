/**
 * Status bar — durum çubuğu bileşeni
 * View'ların içinde embedded olarak kullanılır
 */
import { state, on } from '../state.js';

export function updateStatusBar(data) {
  const el = document.getElementById('status-bar');
  if (!el) return;

  const statusText = el.querySelector('.status-text');
  const statusDot = el.querySelector('.status-dot');

  if (statusDot) {
    statusDot.className = `status-dot ${data.processing ? 'processing' : 'idle'}`;
  }
  if (statusText) {
    statusText.textContent = data.processing ? 'İşleniyor...' : 'Hazır';
  }
}

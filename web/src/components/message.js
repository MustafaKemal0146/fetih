/**
 * Message bubble component — mesaj balonu oluşturucu
 */
import { scrollToBottom } from '../utils.js';

export function createMessageElement(role, content) {
  const div = document.createElement('div');
  div.className = `message ${role}`;
  div.dataset.role = role;

  const isUser = role === 'user';
  const rendered = isUser ? escapeHtml(content) : renderSimpleMarkdown(content || '');

  div.innerHTML = `
    <div class="message-avatar">${isUser ? '👤' : '0️'}</div>
    <div class="message-content">
      <div class="message-author">${isUser ? 'Sen' : 'SETH'}</div>
      <div class="message-bubble">${rendered}</div>
    </div>
  `;

  return div;
}

export function appendMessage(container, role, content) {
  const el = createMessageElement(role, content);
  container.appendChild(el);
  scrollToBottom(container);
  return el;
}

function renderSimpleMarkdown(text) {
  if (!text) return '';
  let html = escapeHtml(text);
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code class="hljs">$2</code></pre>');
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
  html = html.replace(/\n/g, '<br>');
  return html;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Chat view — mesajlaşma arayüzü
 */
import { state, on } from '../state.js';
import { wsSend } from '../ws.js';
import { postChat } from '../api.js';
import { escapeHtml, scrollToBottom } from '../utils.js';

let inputEl, messagesEl, sendBtn, newChatBtn;

export function initializeChatView() {
  inputEl = document.getElementById('chat-input');
  messagesEl = document.getElementById('chat-messages');
  sendBtn = document.getElementById('btn-send');
  newChatBtn = document.getElementById('btn-new-chat');

  if (!inputEl || !sendBtn) return;

  // Send on Enter (not Shift+Enter)
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
    // Prompt history ↑/↓
    if (e.key === 'ArrowUp' && !e.shiftKey) {
      e.preventDefault();
      navigateHistory(-1);
    }
    if (e.key === 'ArrowDown' && !e.shiftKey) {
      e.preventDefault();
      navigateHistory(1);
    }
  });

  // Auto-resize textarea
  inputEl.addEventListener('input', () => {
    inputEl.style.height = 'auto';
    inputEl.style.height = Math.min(inputEl.scrollHeight, 200) + 'px';
  });

  sendBtn.addEventListener('click', sendMessage);
  if (newChatBtn) newChatBtn.addEventListener('click', newChat);

  // State changes
  on('processing', (val) => {
    if (sendBtn) sendBtn.disabled = val;
    if (inputEl) inputEl.disabled = val;
  });
}

export function sendMessage() {
  if (!inputEl) return;
  const text = inputEl.value.trim();
  if (!text || state.processing) return;

  // Add to prompt history
  state.promptHistory = [...(state.promptHistory || []), text];
  state.promptIndex = -1;

  // Render user message
  renderChatMessage({ role: 'user', content: text });

  inputEl.value = '';
  inputEl.style.height = 'auto';

  // Eğer / ile başlıyorsa command event'i olarak gönder
  if (text.startsWith('/')) {
    wsSend('command', text);
  } else {
    wsSend('user_input', text);
    // REST API fallback
    postChat(text).catch(() => {});
  }
}

function newChat() {
  if (messagesEl) messagesEl.innerHTML = '';
  state.messages = [];
  if (inputEl) inputEl.focus();
}

function navigateHistory(dir) {
  const history = state.promptHistory || [];
  if (history.length === 0) return;

  const newIndex = state.promptIndex + dir;
  if (newIndex < -1 || newIndex >= history.length) return;

  state.promptIndex = newIndex;
  if (newIndex === -1) {
    inputEl.value = '';
  } else {
    inputEl.value = history[history.length - 1 - newIndex];
  }
  inputEl.dispatchEvent(new Event('input'));
}

export function renderChatMessage(msg) {
  if (!messagesEl) return;
  const div = document.createElement('div');
  div.className = `message ${msg.role}`;
  div.dataset.role = msg.role;

  const isUser = msg.role === 'user';
  const content = isUser ? escapeHtml(msg.content) : renderMarkdown(msg.content || '');

  div.innerHTML = `
    <div class="message-avatar">${isUser ? '👤' : '0️'}</div>
    <div class="message-content">
      <div class="message-author">${isUser ? 'Sen' : 'FETİH'}</div>
      <div class="message-bubble">${content}</div>
    </div>
  `;

  messagesEl.appendChild(div);
  scrollToBottom(messagesEl);
}

function renderMarkdown(text) {
  if (!text) return '';
  // Simple markdown rendering without marked
  let html = escapeHtml(text);
  // Code blocks
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    return `<pre><code class="hljs ${lang ? `language-${lang}` : ''}">${code}</code></pre>`;
  });
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Bold
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  // Italic
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
  // Line breaks
  html = html.replace(/\n/g, '<br>');
  return html;
}

// escapeHtml ve scrollToBottom utils.js'den import ediliyor

/**
 * Tool call card — tool çağrısı görselleştirme
 */
export function createToolCard(name, input) {
  const card = document.createElement('div');
  card.className = 'tool-card';
  card.dataset.toolName = name;

  card.innerHTML = `
    <div class="tool-card-header" onclick="this.parentElement.classList.toggle('collapsed')">
      <span class="tool-card-icon">🔧</span>
      <span class="tool-card-name">${escapeHtml(name)}</span>
      <span class="tool-card-toggle">▼</span>
    </div>
    <div class="tool-card-body">
      <pre class="tool-card-input">${escapeHtml(JSON.stringify(input, null, 2))}</pre>
      <div class="tool-card-result" style="display:none"></div>
    </div>
  `;

  return card;
}

export function updateToolCardResult(container, name, output, isError) {
  const cards = container.querySelectorAll('.tool-card');
  const card = Array.from(cards).find(c => c.dataset.toolName === name);
  if (!card) return;

  card.classList.remove('collapsed');
  const resultEl = card.querySelector('.tool-card-result');
  if (resultEl) {
    resultEl.textContent = isError ? `❌ ${output}` : `✅ ${output}`;
    resultEl.className = `tool-card-result ${isError ? 'error' : 'success'}`;
    resultEl.style.display = 'block';
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

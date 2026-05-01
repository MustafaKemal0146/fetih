const BASE = '';

export async function fetchStatus() {
  const r = await fetch(`${BASE}/api/status`);
  return r.json();
}

export async function fetchStats() {
  const r = await fetch(`${BASE}/api/stats`);
  return r.json();
}

export async function fetchSessions() {
  const r = await fetch(`${BASE}/api/sessions`);
  return r.json();
}

export async function postAbort() {
  const r = await fetch(`${BASE}/api/abort`, { method: 'POST' });
  return r.json();
}

export async function postChat(message, session) {
  const r = await fetch(`${BASE}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, session }),
  });
  return r;
}

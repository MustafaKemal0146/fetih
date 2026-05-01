import { state } from './state.js';

let ws = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
const MAX_DELAY = 16000;
const handlers = new Map();

export function onWsEvent(type, fn) {
  if (!handlers.has(type)) handlers.set(type, []);
  handlers.get(type).push(fn);
}

function dispatch(type, data) {
  (handlers.get(type) ?? []).forEach(fn => fn(data));
  (handlers.get('*') ?? []).forEach(fn => fn(type, data));
}

export function connectWs() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}`;
  ws = new WebSocket(url);

  ws.addEventListener('open', () => {
    state.connected = true;
    reconnectDelay = 1000;
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    dispatch('connected', null);
  });

  ws.addEventListener('close', () => {
    state.connected = false;
    dispatch('disconnected', null);
    reconnectTimer = setTimeout(() => {
      reconnectDelay = Math.min(reconnectDelay * 2, MAX_DELAY);
      connectWs();
    }, reconnectDelay);
  });

  ws.addEventListener('error', () => {
    ws?.close();
  });

  ws.addEventListener('message', (e) => {
    try {
      const event = JSON.parse(e.data);
      dispatch(event.type, event.data);
    } catch { /* ignore */ }
  });
}

export function wsSend(type, data) {
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type, data }));
  }
}

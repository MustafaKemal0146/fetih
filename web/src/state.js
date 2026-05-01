// Global reactive state via Proxy
const listeners = new Map();

function createState(initial) {
  const state = new Proxy({ ...initial }, {
    set(target, key, value) {
      target[key] = value;
      (listeners.get(key) ?? []).forEach(fn => fn(value));
      (listeners.get('*') ?? []).forEach(fn => fn(key, value));
      return true;
    }
  });
  return state;
}

export const state = createState({
  connected: false,
  processing: false,
  messages: [],
  stats: null,
  daemonStatus: null,
  settings: {},
  effort: 'medium',
  currentView: 'chat',
  promptHistory: [],
  promptIndex: -1,
});

export function on(key, fn) {
  if (!listeners.has(key)) listeners.set(key, []);
  listeners.get(key).push(fn);
  return () => {
    const arr = listeners.get(key) ?? [];
    const i = arr.indexOf(fn);
    if (i !== -1) arr.splice(i, 1);
  };
}

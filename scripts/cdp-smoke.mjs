import WebSocket from 'ws';

const list = await (await fetch('http://127.0.0.1:9222/json/list')).json();
const page = list.find((target) => target.type === 'page');
if (!page) {
  console.log(JSON.stringify({ error: 'no page target' }));
  process.exit(1);
}

const ws = new WebSocket(page.webSocketDebuggerUrl);
let id = 0;
const pending = new Map();

function send(method, params = {}) {
  const messageId = ++id;
  ws.send(JSON.stringify({ id: messageId, method, params }));
  return new Promise((resolve, reject) => {
    pending.set(messageId, { resolve, reject });
    setTimeout(() => reject(new Error(`timeout: ${method}`)), 8000);
  });
}

ws.on('message', (raw) => {
  const message = JSON.parse(raw.toString());
  if (message.id && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(JSON.stringify(message.error)));
    else resolve(message.result);
  }
});

await new Promise((resolve, reject) => {
  ws.on('open', resolve);
  ws.on('error', reject);
});

const expression = `(() => {
  const setup = document.querySelector('#server-view');
  const auth = document.querySelector('#auth-view');
  return JSON.stringify({
    url: location.href,
    injectedServer: typeof window.__AEGIS_SERVER__,
    setupVisible: setup ? !setup.classList.contains('hidden') : null,
    authHidden: auth ? auth.classList.contains('hidden') : null,
    socketIoLoaded: typeof window.io,
    naclLoaded: typeof window.nacl,
    setupHeading: document.querySelector('#server-title')?.textContent ?? null,
    formPlaceholder: document.querySelector('#server-form input')?.placeholder ?? null,
  });
})()`;

const result = await send('Runtime.evaluate', { expression, returnByValue: true });
console.log(result.result?.value ?? JSON.stringify(result));
ws.close();

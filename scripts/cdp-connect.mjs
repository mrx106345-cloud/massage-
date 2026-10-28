import WebSocket from 'ws';

const cdpPort = process.env.CDP_PORT ?? '9222';
const list = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
const page = list.find((target) => target.type === 'page');
if (!page) throw new Error('no page target');

const ws = new WebSocket(page.webSocketDebuggerUrl);
let id = 0;
const pending = new Map();

function send(method, params = {}) {
  const messageId = ++id;
  ws.send(JSON.stringify({ id: messageId, method, params }));
  return new Promise((resolve, reject) => {
    pending.set(messageId, { resolve, reject });
    setTimeout(() => reject(new Error(`timeout: ${method}`)), 15000);
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

async function evaluate(expression) {
  const result = await send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result?.value;
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// 1. Submit the setup form exactly as a user would.
await evaluate(`(() => {
  const input = document.querySelector('#server-form input[name="server"]');
  input.value = 'http://localhost:4000';
  document.querySelector('#server-form').requestSubmit();
  return true;
})()`);

await wait(3000);

console.log(
  'after setup:',
  await evaluate(`JSON.stringify({
    url: location.href,
    stored: localStorage.getItem('aegis.server'),
    authVisible: !document.querySelector('#auth-view').classList.contains('hidden'),
    setupVisible: !document.querySelector('#server-view').classList.contains('hidden'),
  })`),
);

// 2. Sign in against the remote server from the app:// origin.
await evaluate(`(() => {
  const form = document.querySelector('#login-form');
  form.querySelector('input[name="email"]').value = 'dana@example.com';
  form.querySelector('input[name="password"]').value = 'Password123!';
  form.requestSubmit();
  return true;
})()`);

await wait(4000);

console.log(
  'after login:',
  await evaluate(`JSON.stringify({
    appVisible: !document.querySelector('#app-view').classList.contains('hidden'),
    meName: document.querySelector('#me-name')?.textContent ?? null,
    relay: document.querySelector('#relay-state')?.textContent ?? null,
    loginError: document.querySelector('#login-error')?.textContent ?? null,
  })`),
);

ws.close();

/**
 * Aegis Chat desktop shell.
 *
 * The renderer is the same client the web build serves, packed into the app and
 * exposed over a privileged `app://aegis` scheme. Everything sensitive stays in
 * the page: this process only loads files, remembers which server the user
 * chose, and never sees message content or keys.
 *
 *   app://aegis/index.html  ->  <resources>/public/index.html
 */

const { app, BrowserWindow, Menu, ipcMain, protocol, shell } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const SCHEME = 'app';
const HOST = 'aegis';
const APP_ORIGIN = `${SCHEME}://${HOST}`;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const CONFIG_FILE = () => path.join(app.getPath('userData'), 'server.json');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon',
};

function readConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_FILE(), 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed.server === 'string' ? parsed : { server: '' };
  } catch {
    return { server: '' };
  }
}

function writeConfig(config) {
  try {
    fs.mkdirSync(path.dirname(CONFIG_FILE()), { recursive: true });
    fs.writeFileSync(CONFIG_FILE(), JSON.stringify(config, null, 2));
  } catch (error) {
    console.error('[aegis] could not persist server config:', error);
  }
}

/** Map an `app://aegis/...` request to a file, refusing traversal. */
function resolveAsset(requestUrl) {
  const url = new URL(requestUrl);
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/' || pathname === '') pathname = '/index.html';

  const relative = pathname.replace(/^\/+/, '');
  const resolved = path.resolve(PUBLIC_DIR, relative);
  const root = path.resolve(PUBLIC_DIR);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) return null;
  return resolved;
}

// Must run before `ready`: a privileged scheme gets a real origin, so fetch,
// modules and the WebSocket handshake behave exactly as they do on the web.
protocol.registerSchemesAsPrivileged([
  {
    scheme: SCHEME,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
      stream: true,
    },
  },
]);

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0b1220',
    title: 'Aegis Chat',
    autoHideMenuBar: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: true,
    },
  });

  // External links open in the user's browser; the app window never navigates
  // away from the bundled client.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) void shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith(APP_ORIGIN)) {
      event.preventDefault();
      if (/^https?:\/\//i.test(url)) void shell.openExternal(url);
    }
  });

  void mainWindow.loadURL(`${APP_ORIGIN}/index.html`);
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function buildMenu() {
  const template = [
    ...(process.platform === 'darwin'
      ? [
          {
            label: app.name,
            submenu: [{ role: 'about' }, { type: 'separator' }, { role: 'hide' }, { role: 'quit' }],
          },
        ]
      : []),
    {
      label: 'File',
      submenu: [
        {
          label: 'Change server…',
          click: () => {
            writeConfig({ server: '' });
            if (mainWindow) void mainWindow.loadURL(`${APP_ORIGIN}/index.html`);
          },
        },
        { type: 'separator' },
        process.platform === 'darwin' ? { role: 'close' } : { role: 'quit' },
      ],
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
        { role: 'toggleDevTools' },
      ],
    },
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(() => {
  protocol.handle(SCHEME, async (request) => {
    const filePath = resolveAsset(request.url);
    if (!filePath) return new Response('Not found', { status: 404 });

    const securityHeaders = {
      'content-type': MIME_TYPES[path.extname(filePath).toLowerCase()] ?? 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      // Allow inline scripts/styles for the bundled client; same as web build
      'Content-Security-Policy':
        "default-src 'self' app:; script-src 'self' 'unsafe-inline' 'unsafe-eval' app:; style-src 'self' 'unsafe-inline' app:; img-src 'self' data: blob: https: app:; connect-src 'self' ws: wss: https: http: app:; font-src 'self' data: app:; media-src 'self' blob:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    };

    try {
      const body = await fs.promises.readFile(filePath);
      return new Response(body, { headers: securityHeaders });
    } catch {
      // Unknown asset: fall back to the shell so a deep link still boots.
      try {
        const index = await fs.promises.readFile(path.join(PUBLIC_DIR, 'index.html'));
        return new Response(index, {
          headers: { ...securityHeaders, 'content-type': MIME_TYPES['.html'] },
        });
      } catch {
        return new Response('Not found', { status: 404 });
      }
    }
  });

  ipcMain.on('aegis:get-server', (event) => {
    event.returnValue = readConfig().server;
  });

  buildMenu();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Nothing should spawn a second instance with a different server; focus instead.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

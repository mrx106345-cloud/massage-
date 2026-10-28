/**
 * Only one thing crosses the bridge: the server origin the user configured.
 * The renderer stays isolated — no filesystem, no shell, no Node globals.
 */
const { contextBridge, ipcRenderer } = require('electron');

let server = '';
try {
  server = String(ipcRenderer.sendSync('aegis:get-server') ?? '');
} catch {
  server = '';
}

contextBridge.exposeInMainWorld('__AEGIS_SERVER__', server);

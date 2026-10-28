#!/usr/bin/env node
/**
 * Copy the Socket.IO browser bundle into `public/vendor`.
 *
 * The web build used to load `/socket.io/socket.io.js` from the API server. A
 * packaged desktop/mobile build has no local API server, so the client must ship
 * with the app and only the socket transport talks to the remote host.
 */

const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const source = path.join(root, 'node_modules', 'socket.io-client', 'dist', 'socket.io.min.js');
const targetDir = path.join(root, 'public', 'vendor');
const target = path.join(targetDir, 'socket.io.min.js');

if (!fs.existsSync(source)) {
  console.error('[vendor] socket.io-client is not installed; run npm install first');
  process.exit(1);
}

fs.mkdirSync(targetDir, { recursive: true });
fs.copyFileSync(source, target);

const version = require(
  path.join(root, 'node_modules', 'socket.io-client', 'package.json'),
).version;
console.log(`[vendor] socket.io-client ${version} -> public/vendor/socket.io.min.js`);

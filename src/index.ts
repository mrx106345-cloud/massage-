import * as http from 'node:http';
import { Server } from 'socket.io';
import 'dotenv/config';
import app from './app.js';
import { createSchema, deleteRows, selectAll, shutdown as shutdownDb } from './db/index.js';
import { createSocketServer } from './sockets/server.js';
import { closeCache } from './services/cache.js';
import type { SocketContext } from './sockets/types.js';
import { cfg, clientOrigins } from './config/index.js';

const PORT = cfg.PORT;
const HOST = cfg.HOST;
const USE_SOCKET = cfg.SOCKET_ENABLED;

const server = http.createServer(app);
const SOCKET_POLL_INTERVAL_MS = 5000;

let io: Server | null = null;
let socketCtx: SocketContext | null = null;

if (USE_SOCKET) {
  io = new Server(server, {
    cors: {
      // Same allowlist as HTTP: configured hosts plus the packaged app shells.
      origin: clientOrigins(),
      methods: ['GET', 'POST'],
    },
    path: '/socket.io',
  });

  socketCtx = { io, users: new Map(), httpServer: server };
  createSocketServer(socketCtx);

  // Periodically flush the offline queue into connected sockets (best-effort).
  setInterval(() => {
    void drainOfflineQueue().catch((error) => {
      console.error('[offline-queue] flush failed:', error);
    });
  }, SOCKET_POLL_INTERVAL_MS).unref();
}

async function drainOfflineQueue(): Promise<void> {
  if (!socketCtx) return;
  const rows = await selectAll('offline_queue_item', { status: 'queued' }, 50);
  for (const row of rows) {
    const userId = String(row.user_id);
    const sockets = socketCtx.users.get(userId);
    if (!sockets || sockets.size === 0) continue;

    for (const socket of sockets) {
      try {
        socket.emit('receive_message', row.payload);
      } catch {
        // socket already closed
      }
    }
    await deleteRows('offline_queue_item', { id: String(row.id), status: 'queued' });
  }
}

async function bootstrap() {
  if (cfg.AUTO_MIGRATE) {
    try {
      await createSchema();
      console.log('[db] schema ready');
    } catch (error) {
      console.error('[startup] schema initialisation failed:', error);
      process.exit(1);
    }
  }

  return server.listen(PORT, HOST, () => {
    const address = serverHttp.address();
    const boundPort = typeof address === 'object' && address ? address.port : PORT;
    console.log(`[api] HTTP  listening on http://${HOST}:${boundPort}`);
    console.log(`[api] Docs at http://${HOST}:${boundPort}/api/docs`);
    if (USE_SOCKET) {
      console.log(`[socket] Socket.IO  listening on /socket.io`);
    }
  });
}

const serverHttp = await bootstrap();

let shuttingDown = false;

function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n[signal] ${signal} received; shutting down...`);

  serverHttp.close(() => {
    Promise.allSettled([shutdownDb(), closeCache()])
      .then(() => process.exit(0))
      .catch(() => process.exit(0));
  });
  // Force-exit if connections refuse to drain.
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  console.error('[startup] uncaughtException:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[startup] unhandledRejection:', reason);
});

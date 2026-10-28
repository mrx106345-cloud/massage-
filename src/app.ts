import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Express } from 'express';
import compression from 'compression';
import 'dotenv/config';
import { cfg, _isProduction, hasMetricsAuth } from './config/index.js';
import {
  initSecurityHeaders,
  initCors,
  initBodyLimits,
  initMaintenanceMode,
  initTrustProxy,
} from './middleware/security.js';
import { logger } from './utils/logger.js';
import { generateRequestId } from './middleware/security.js';
import { asyncRoute } from './middleware/async.js';
import { signup, login, requireAuth, refreshToken } from './services/auth.service.js';
import { authLimiter, globalLimiter } from './middleware/rateLimiter.js';
import { rawQuery, selectAll } from './db/index.js';
import { accountRouter, authFlowRouter } from './routes/account.routes.js';
import { docsRouter } from './routes/docs.routes.js';
import { openApiDocument } from './openapi.js';
import { getOutbox } from './services/mailer.service.js';
import {
  presignMediaUpload,
  getMedia,
  handleLocalUpload,
  handleLocalDownload,
} from './services/media.service.js';
import { listThreads, getThreadMessages, markThreadRead } from './services/threads.service.js';
import {
  createGroup,
  listGroups,
  getGroup,
  updateGroup,
  deleteGroup,
  addMembers,
  removeMember,
  leaveGroup,
} from './services/groups.service.js';
import {
  livenessCheck,
  readinessCheck,
  detailedHealthCheck,
  metricsHandler,
} from './services/health.service.js';
import { getSelfE2EEContext, provisionSelfE2EEContext } from './services/crypto.service.js';

const app: Express = express();

// The browser client lives in `public/` and is served by this process, so the
// API and the app share an origin (cookies-free bearer auth, no CORS surface).
const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const hasClient = fs.existsSync(path.join(publicDir, 'index.html'));

// ---------------------------------------------------------------------------
// Middleware setup
// ---------------------------------------------------------------------------

// Trust proxy (for rate limiting behind reverse proxy)
initTrustProxy(app);

// Security headers (Helmet)
initSecurityHeaders(app);

// CORS
initCors(app);

// Body size limits
initBodyLimits(app);

// Response compression
app.use(compression());

// Static client assets. `index: false` keeps `/` behind the explicit route
// below so it can be served with a no-cache policy.
if (hasClient) {
  app.use(
    express.static(publicDir, {
      index: false,
      // Dev must never serve a stale bundle from cache; production can hold the
      // (unhashed) assets for an hour behind ETag revalidation.
      maxAge: cfg.NODE_ENV === 'production' ? '1h' : 0,
      setHeaders: (res) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        if (cfg.NODE_ENV !== 'production') res.setHeader('Cache-Control', 'no-store');
      },
    }),
  );
}

// Maintenance mode (if enabled)
initMaintenanceMode(app);

// Global flood protection (health/metrics/docs are exempt)
app.use(globalLimiter);

// Request correlation + structured request logging. The id is assigned before
// the child logger is created so every log line carries the same id that is
// returned to the client in the X-Request-ID header.
app.use((req, res, next) => {
  const incoming = req.headers['x-request-id'];
  const requestId =
    typeof incoming === 'string' && incoming.length > 0 && incoming.length <= 128
      ? incoming
      : generateRequestId();
  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);

  const start = Date.now();
  const requestLogger = logger.child({
    requestId,
    method: req.method,
    path: req.path,
    userAgent: req.headers['user-agent'],
    ip: req.ip ?? req.socket?.remoteAddress,
  });
  (req as any).logger = requestLogger;

  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    requestLogger[level](
      { res: { status: res.statusCode, durationMs: duration } },
      `${req.method} ${req.path} -> ${res.statusCode} (${duration}ms)`,
    );
  });

  next();
});

// ---------------------------------------------------------------------------
// Health check endpoints
// ---------------------------------------------------------------------------

app.get('/api/health', asyncRoute(livenessCheck));

app.get('/api/health/ready', asyncRoute(readinessCheck));
app.get('/api/health/detailed', asyncRoute(detailedHealthCheck));

app.get(
  '/api/metrics',
  asyncRoute((req, res) => {
    // In production, gate runtime metrics behind a bearer token so operational
    // details are not exposed publicly. In dev/test the endpoint stays open so
    // local tooling can inspect it without extra setup.
    if (hasMetricsAuth) {
      if (req.headers.authorization !== `Bearer ${cfg.METRICS_TOKEN}`) {
        return res.status(401).json({ error: 'invalid metrics token' });
      }
    }
    return metricsHandler(req, res);
  }),
);

// API documentation
app.get('/api/openapi.json', (_req, res) => res.json(openApiDocument));
app.use('/api/docs', docsRouter);

app.get('/api/version', (_req, res) =>
  res.json({
    version: process.env.npm_package_version ?? '1.0.0',
    name: 'aegis-secure-chat',
    environment: cfg.NODE_ENV,
    nodeVersion: process.version,
  }),
);

// Dev-only mail outbox so verification/reset links are discoverable locally.
if (cfg.NODE_ENV !== 'production') {
  app.get('/__dev__/outbox', (_req, res) => res.json({ messages: getOutbox() }));
}

app.post(
  '/api/v1/auth/signup',
  authLimiter,
  asyncRoute((req, res) => signup(req, res)),
);
app.post(
  '/api/v1/auth/login',
  authLimiter,
  asyncRoute((req, res) => login(req, res)),
);
app.post(
  '/api/v1/auth/refresh',
  asyncRoute((req, res) => refreshToken(req, res)),
);

// Extended auth flows: verification, password reset, 2FA, logout.
app.use('/api/v1/auth', authFlowRouter);

// Account management: sessions, export, deletion, audit trail.
app.use('/api/v1/account', accountRouter);

// ---- Users ---------------------------------------------------------
// Search by username. Email addresses are deliberately never returned: lookup
// must not double as an address-harvesting endpoint.
app.get(
  '/api/v1/users/search',
  requireAuth,
  asyncRoute(async (req, res) => {
    const raw = typeof req.query.q === 'string' ? req.query.q.trim() : '';
    if (!raw) return res.status(400).json({ error: 'q is required' });
    if (raw.length > 64) return res.status(400).json({ error: 'q must be 64 characters or fewer' });

    // Literal substring match: `%`, `_` and `\\` in the query are escaped and
    // matched through an explicit ESCAPE clause, so a username like `e2e_bob`
    // is searchable and `%` cannot be used as a wildcard. LOWER() keeps the
    // comparison case-insensitive on PostgreSQL as well as SQLite.
    const pattern = `%${raw.replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
    const rows = await rawQuery(
      `SELECT id, username, avatar_url, is_online, created_at, updated_at
         FROM "user"
        WHERE LOWER(username) LIKE LOWER(?) ESCAPE '\\'
        ORDER BY username
        LIMIT 20`,
      [pattern],
    );
    res.json({
      users: rows.map((row) => ({
        id: row.id,
        username: row.username,
        avatar_url: row.avatar_url,
        is_online: Boolean(row.is_online),
        created_at: row.created_at,
        updated_at: row.updated_at,
      })),
    });
  }),
);

// Public key exchange (RFC 001 §2): returns the active X25519 identity key the
// user published over the socket channel, so peers can start a session.
app.get(
  '/api/v1/users/:id/public-key',
  requireAuth,
  asyncRoute(async (req, res) => {
    const targetId = req.params.id;
    const keys = await selectAll(
      'crypto_key',
      { owner_id: targetId, status: 'active' },
      1,
      [
        'key_id',
        'x25519_public',
        'curve25519_public',
        'ed25519_public',
        'public_key_pem',
        'created_at',
      ],
      { column: 'created_at', direction: 'desc' },
    );
    const key = keys[0];
    if (!key) {
      return res.status(404).json({ error: 'no published key for this user' });
    }
    return res.json({
      keyId: key.key_id,
      publicKey: key.public_key_pem ?? key.x25519_public ?? null,
      x25519_public: key.x25519_public ?? null,
      curve25519_public: key.curve25519_public ?? null,
      signingPublicKey: key.ed25519_public ?? null,
      ed25519_public: key.ed25519_public ?? null,
      createdAt: key.created_at,
    });
  }),
);

// E2EE key management (RFC 001 §1 + §3). Own identity + prekey bundle.
app.get(
  '/api/v1/crypto/keys/self',
  requireAuth,
  asyncRoute((req, res) => getSelfE2EEContext(req as any, res)),
);

app.post(
  '/api/v1/crypto/keys/self',
  requireAuth,
  asyncRoute((req, res) => provisionSelfE2EEContext(req as any, res)),
);

// ---- Threads -----------------------------------------------------------
// Conversation list and paginated ciphertext history. Both are participant
// scoped: a thread id is not a capability.
app.get(
  '/api/v1/threads',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => listThreads(req as any, res)),
);
app.get(
  '/api/v1/threads/:threadId/messages',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => getThreadMessages(req as any, res)),
);
app.post(
  '/api/v1/threads/:threadId/read',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => markThreadRead(req as any, res)),
);

// ---- Media -------------------------------------------------------------
app.post(
  '/api/v1/media/presign',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => presignMediaUpload(req as any, res)),
);
// Credential-free local storage fallback. Authorisation is carried by the HMAC
// signature on the query string produced at presign time, so these routes are
// intentionally registered before the `:mediaId` lookup.
app.put('/api/v1/media/upload/local', asyncRoute(handleLocalUpload));
app.get('/api/v1/media/download/local', asyncRoute(handleLocalDownload));
app.get(
  '/api/v1/media/:mediaId',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => getMedia(req as any, res)),
);

// ---- Groups ------------------------------------------------------------
app.post(
  '/api/v1/groups',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => createGroup(req as any, res)),
);
app.get(
  '/api/v1/groups',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => listGroups(req as any, res)),
);
app.get(
  '/api/v1/groups/:groupId',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => getGroup(req as any, res)),
);
app.put(
  '/api/v1/groups/:groupId',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => updateGroup(req as any, res)),
);
app.delete(
  '/api/v1/groups/:groupId',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => deleteGroup(req as any, res)),
);
app.post(
  '/api/v1/groups/:groupId/members',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => addMembers(req as any, res)),
);
app.delete(
  '/api/v1/groups/:groupId/members/:memberId',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => removeMember(req as any, res)),
);
app.post(
  '/api/v1/groups/:groupId/leave',
  asyncRoute(requireAuth),
  asyncRoute((req, res) => leaveGroup(req as any, res)),
);

// ---------------------------------------------------------------------------
// Web client (SPA entry point)
// ---------------------------------------------------------------------------
app.get('/', (_req, res, next) => {
  if (!hasClient) return next();
  res.setHeader('Cache-Control', 'no-cache');
  return res.sendFile(path.join(publicDir, 'index.html'));
});

// ---------------------------------------------------------------------------
// 404 handler
// ---------------------------------------------------------------------------
app.use((_req, res) => {
  res.status(404).json({
    error: 'not found',
    path: _req.path,
    method: _req.method,
  });
});

// ---------------------------------------------------------------------------
// Global error handler
// ---------------------------------------------------------------------------
app.use((err: unknown, req: any, res: any, _next: (err?: unknown) => void) => {
  const requestLogger = (req as any).logger ?? logger;
  const status = (
    err && typeof (err as any).status === 'number' ? (err as any).status : 500
  ) as number;
  const message = (
    err && typeof (err as any).message === 'string' ? (err as any).message : 'internal server error'
  ) as string;

  requestLogger.error(
    {
      err: err instanceof Error ? { message: err.message, stack: err.stack } : err,
      status,
      method: req.method,
      path: req.path,
    },
    `Request failed: ${req.method} ${req.path} -> ${status}`,
  );

  // Don't leak error details in production
  const responseMessage =
    cfg.NODE_ENV === 'production' && status >= 500 ? 'internal server error' : message;

  res.status(status).json({
    error: responseMessage,
    requestId: req.headers['x-request-id'],
  });
});

export default app;

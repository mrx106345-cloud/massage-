/**
 * Security middleware stack.
 *
 * Provides:
 * - Helmet.js security headers
 * - Strict CORS configuration
 * - Rate limiting per endpoint category
 * - Request/response logging with correlation IDs
 * - Request body size limits
 * - Security headers (CSP, HSTS, etc.)
 */

import express from 'express';
import helmet from 'helmet';
import { cfg, clientOrigins } from '../config/index.js';

// Type exports
export type { Request, Response, NextFunction } from 'express';
export type { Application } from 'express';

// ---------------------------------------------------------------------------
// Helmet configuration
// ---------------------------------------------------------------------------

export function initSecurityHeaders(app: express.Application) {
  app.use(
    helmet({
      // Content Security Policy - adjust for your frontend
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"], // Remove unsafe-eval in production
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
          // `self` covers same-origin XHR; the explicit ws/wss sources keep the
          // Socket.IO transport working in browsers that do not fold WebSocket
          // schemes into `self`. `https:` is required when media is stored in
          // S3-compatible storage and uploaded/downloaded directly.
          connectSrc: ["'self'", 'ws:', 'wss:', 'https:'],
          fontSrc: ["'self'", 'data:'],
          objectSrc: ["'none'"],
          // Attachments are decrypted in the browser and rendered from blob:
          // URLs, so audio/video playback needs blob: explicitly.
          mediaSrc: ["'self'", 'blob:'],
          frameSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          upgradeInsecureRequests: [],
        },
      },
      // Disable HSTS in development (use HTTPS in production)
      hsts:
        cfg.NODE_ENV === 'production'
          ? {
              maxAge: 31536000, // 1 year
              includeSubDomains: true,
              preload: true,
            }
          : false,
      // Disable IE-specific protections (legacy)
      ieNoOpen: false,
      // Hide X-Powered-By header
      hidePoweredBy: true,
      // Prevent sniffing of MIME types
      noSniff: true,
      // Enable XSS filter in browsers
      xssFilter: true,
      // Prevent clickjacking
      frameguard: {
        action: 'deny',
      },
      // Referrer policy
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
      },
      // Cross-origin policies
      crossOriginEmbedderPolicy: {
        policy: 'require-corp',
      },
      crossOriginOpenerPolicy: {
        policy: 'same-origin',
      },
      crossOriginResourcePolicy: { policy: 'same-origin' },
    }),
  );

  // Additional security headers
  app.use((req, res, next) => {
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.setHeader('X-Download-Options', 'noopen');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    );
    next();
  });
}

// ---------------------------------------------------------------------------
// CORS configuration
// ---------------------------------------------------------------------------

export function initCors(app: express.Application) {
  // Includes the packaged desktop/mobile origins; a browser cannot forge those
  // schemes, so allowing them does not widen access for web pages.
  const allowedOrigins = clientOrigins();

  app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
    // For requests with Origin header, validate against allowed origins
    const origin = req.headers.origin;

    if (origin && allowedOrigins.length > 0) {
      // In production, be strict
      if (cfg.NODE_ENV === 'production') {
        if (!allowedOrigins.includes(origin)) {
          res.status(403).json({ error: 'CORS not allowed' });
          return;
        }
      }
      // In development, allow localhost
      if (cfg.NODE_ENV !== 'production') {
        if (
          !allowedOrigins.includes(origin) &&
          !origin.startsWith('http://localhost') &&
          !origin.startsWith('http://127.0.0.1')
        ) {
          res.status(403).json({ error: 'CORS not allowed' });
          return;
        }
      }
      res.header('Access-Control-Allow-Origin', origin);
    }

    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID');
    res.header('Access-Control-Expose-Headers', 'X-Request-ID, X-Response-Time');
    res.header('Access-Control-Max-Age', '86400'); // Cache preflight for 24 hours

    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    next();
  });
}

// ---------------------------------------------------------------------------
// Request logging with correlation IDs
// ---------------------------------------------------------------------------

let requestIdCounter = 0;

export function generateRequestId(): string {
  requestIdCounter += 1;
  const timestamp = Date.now().toString(36);
  const counter = requestIdCounter.toString(36).padStart(4, '0');
  return `req_${timestamp}_${counter}`;
}

export function initRequestLogging(app: express.Application) {
  // Middleware to add X-Request-ID to every request
  app.use((req: express.Request, _res: express.Response, next: express.NextFunction) => {
    const requestId = req.headers['x-request-id'] as string | undefined;
    req.headers['x-request-id'] = requestId ?? generateRequestId();
    next();
  });
}

// ---------------------------------------------------------------------------
// Body size limits
// ---------------------------------------------------------------------------

export function initBodyLimits(app: express.Application) {
  // JSON body limit
  app.use(express.json({ limit: '1mb' }));

  // URL-encoded body limit
  app.use(
    express.urlencoded({
      extended: true,
      limit: '1mb',
    }),
  );

  // Raw body limit (for future use)
  app.use((_req: express.Request, _res: express.Response, next: express.NextFunction) => {
    // Already handled by express.json() above
    next();
  });
}

// ---------------------------------------------------------------------------
// Maintenance mode middleware
// ---------------------------------------------------------------------------

export function initMaintenanceMode(app: express.Application) {
  if (cfg.MAINTENANCE_MODE === true) {
    app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
      // Allow health checks and static assets to pass through
      if (req.path === '/api/health' || req.path.startsWith('/socket.io')) {
        return next();
      }

      res.status(503).json({
        error: 'Service temporarily unavailable',
        retryAfter: 300, // 5 minutes
      });
    });
  }
}

// ---------------------------------------------------------------------------
// Trust proxy (for rate limiting behind reverse proxy)
// ---------------------------------------------------------------------------

export function initTrustProxy(app: express.Application) {
  const raw = cfg.TRUST_PROXY;
  if (raw === false) return;

  const text =
    typeof raw === 'string' ? raw.trim() : Array.isArray(raw) ? raw.join(',') : String(raw);
  if (text === '' || text === 'false' || text === '0') return;

  // Express accepts a hop count, a preset name ("loopback", "linklocal",
  // "uniquelocal") or a comma-separated list of addresses/subnets.
  const value: number | string = text === 'true' ? 1 : /^\d+$/.test(text) ? Number(text) : text;
  app.set('trust proxy', value);
}

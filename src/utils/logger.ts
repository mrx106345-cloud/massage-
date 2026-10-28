/**
 * Structured logging with pino.
 *
 * Provides:
 * - JSON-formatted logs in production
 * - Human-readable logs in development
 * - Correlation ID tracking
 * - Request context attachment
 * - Log levels: trace, debug, info, warn, error, fatal
 */

import { createRequire } from 'node:module';
import pino, { type Logger } from 'pino';
import { cfg } from '../config/index.js';

const requireHere = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// Logger configuration
// ---------------------------------------------------------------------------

const isProduction = cfg.NODE_ENV === 'production';
const isTest = cfg.NODE_ENV === 'test';

// In test mode, suppress all logs (tests will use their own assertions)
const logLevel = isTest ? 'fatal' : isProduction ? 'info' : 'debug';

// Pretty print in development when `pino-pretty` is installed; JSON otherwise.
// Resolving the target lazily keeps production/test output as plain JSON and
// avoids a hard dependency (pino-pretty is a dev-only convenience).
function prettyTransport() {
  if (isProduction || isTest) return undefined;
  try {
    requireHere.resolve('pino-pretty');
  } catch {
    return undefined;
  }
  return {
    target: 'pino-pretty',
    options: {
      translateTime: 'HH:MM:ss Z',
      ignore: 'pid,hostname',
      colorize: true,
    },
  };
}

const transport = prettyTransport();

export const logger = pino({
  level: logLevel,
  transport,
  base: {
    env: cfg.NODE_ENV,
    service: 'aegis-chat-api',
    version: process.env.npm_package_version ?? '1.0.0',
  },
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'password',
      'password_hash',
      'secret',
      'api_key',
      'token',
    ],
    censor: '***REDACTED***',
  },
});

// ---------------------------------------------------------------------------
// Request-scoped logger (with correlation ID)
// ---------------------------------------------------------------------------

export interface LoggerContext {
  requestId: string;
  method: string;
  path: string;
  userAgent?: string;
  ip?: string;
  userId?: string | undefined;
}

export function createRequestLogger(ctx: LoggerContext) {
  const childBindings: Record<string, unknown> = {
    requestId: ctx.requestId,
    method: ctx.method,
    path: ctx.path,
  };
  if (ctx.userAgent) childBindings.userAgent = ctx.userAgent;
  if (ctx.ip) childBindings.ip = ctx.ip;
  if (ctx.userId) childBindings.userId = ctx.userId;
  return logger.child(childBindings);
}

// ---------------------------------------------------------------------------
// Helper to extract request context
// ---------------------------------------------------------------------------

export function getRequestContext(req: {
  headers: Record<string, string | undefined>;
  method: string;
  path: string;
  socket?: { remoteAddress?: string };
  user?: { id?: string };
}) {
  return {
    requestId: (req.headers['x-request-id'] as string) ?? 'unknown',
    method: req.method,
    path: req.path,
    userAgent: req.headers['user-agent'],
    ip: req.socket?.remoteAddress,
    userId: req.user?.id,
  };
}

// ---------------------------------------------------------------------------
// Log formatting helpers
// ---------------------------------------------------------------------------

export function logRequest(
  logger: Logger,
  req: { method: string; path: string; headers: Record<string, string | undefined> },
  status: number,
  duration: number,
) {
  const level = status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info';
  logger[level](
    {
      req: {
        method: req.method,
        path: req.path,
      },
      res: {
        status,
        durationMs: Math.round(duration),
      },
    },
    `${req.method} ${req.path} -> ${status} (${Math.round(duration)}ms)`,
  );
}

// ---------------------------------------------------------------------------
// Performance monitoring
// ---------------------------------------------------------------------------

// Performance monitoring helper (optional)
export async function monitorPerformance<T>(
  logger: Logger,
  name: string,
  fn: () => Promise<T> | T,
): Promise<T> {
  const start = performance.now();
  try {
    const result = fn();
    if (result instanceof Promise) {
      return result.then((value) => {
        const duration = performance.now() - start;
        logger.debug(
          { name, durationMs: Math.round(duration * 1000) },
          `Performance: ${name} completed`,
        );
        return value;
      });
    }
    const duration = performance.now() - start;
    logger.debug(
      { name, durationMs: Math.round(duration * 1000) },
      `Performance: ${name} completed`,
    );
    return result as T;
  } catch (error) {
    const duration = performance.now() - start;
    logger.error(
      {
        name,
        durationMs: Math.round(duration * 1000),
        error: error instanceof Error ? { message: error.message } : error,
      },
      `Performance: ${name} failed`,
    );
    throw error;
  }
}

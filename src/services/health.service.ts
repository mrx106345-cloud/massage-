/**
 * Health check and metrics service.
 *
 * Provides:
 * - Liveness probe (is the server running?)
 * - Readiness probe (is the server ready to serve traffic?)
 * - Detailed health status (database, redis, dependencies)
 * - Basic metrics (request counts, latency, etc.)
 */

import { type Request, type Response } from 'express';
import { db } from '../db/index.js';
import { cfg } from '../config/index.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HealthStatus {
  status: 'ok' | 'degraded' | 'down';
  version: string;
  timestamp: string;
  uptime: number;
  dependencies: {
    database: DependencyStatus;
    redis?: DependencyStatus;
  };
  checks: Record<string, CheckResult>;
}

export interface DependencyStatus {
  status: 'ok' | 'down' | 'disabled';
  latencyMs?: number;
  message?: string;
}

export interface CheckResult {
  ok: boolean;
  message?: string;
  details?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Health check endpoints
// ---------------------------------------------------------------------------

export async function livenessCheck(_req: Request, res: Response) {
  // Simple liveness check - just confirms the server is running
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
}

export async function readinessCheck(req: Request, res: Response) {
  // Readiness check - confirms the server is ready to handle requests
  const checks: CheckResult[] = [];

  // Check database connectivity
  try {
    // Try a simple query
    await db.selectFrom('user').select('id').limit(1).execute();
    checks.push({ ok: true, message: 'Database connected' });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    checks.push({ ok: false, message });
  }

  // Check if all required checks passed
  const allOk = checks.every((c) => c.ok);

  if (allOk) {
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      checks,
    });
  } else {
    res.status(503).json({
      status: 'down',
      timestamp: new Date().toISOString(),
      checks,
    });
  }
}

export async function detailedHealthCheck(req: Request, res: Response) {
  const startTime = Date.now();

  const health: HealthStatus = {
    status: 'ok',
    version: process.env.npm_package_version ?? '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    dependencies: {
      database: { status: 'disabled' },
    },
    checks: {},
  };

  // Check database
  try {
    const dbStart = Date.now();
    await db.selectFrom('user').select('id').limit(1).execute();
    const dbLatency = Date.now() - dbStart;
    health.dependencies.database = {
      status: 'ok',
      latencyMs: dbLatency,
    };
    health.checks.database = { ok: true, details: { latencyMs: dbLatency } };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    health.dependencies.database = { status: 'down', message };
    health.checks.database = { ok: false, message };
    health.status = 'degraded';
  }

  // Check Redis (if configured)
  if (cfg.REDIS_URL) {
    try {
      const redis = new (await import('ioredis')).Redis(cfg.REDIS_URL);
      const redisStart = Date.now();
      await redis.ping();
      await redis.quit();
      const redisLatency = Date.now() - redisStart;
      health.dependencies.redis = {
        status: 'ok',
        latencyMs: redisLatency,
      };
      health.checks.redis = { ok: true, details: { latencyMs: redisLatency } };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      health.dependencies.redis = { status: 'down', message };
      health.checks.redis = { ok: false, message };
      health.status = 'degraded';
    }
  }

  // Set overall status
  if (health.dependencies.database.status === 'down') {
    health.status = 'down';
  } else if (Object.values(health.checks).some((c) => !c.ok)) {
    health.status = 'degraded';
  }

  // Add response time
  health.checks.responseTime = { ok: true, details: { latencyMs: Date.now() - startTime } };

  const statusCode = health.status === 'ok' ? 200 : health.status === 'degraded' ? 200 : 503;

  res.status(statusCode).json(health);
}

// ---------------------------------------------------------------------------
// Metrics endpoint (basic)
// ---------------------------------------------------------------------------

export async function metricsHandler(req: Request, res: Response) {
  // Basic application metrics
  // In production, you'd want to integrate with Prometheus or similar

  const metrics = {
    app: {
      name: 'aegis-chat-api',
      version: process.env.npm_package_version ?? '1.0.0',
      environment: cfg.NODE_ENV,
      uptimeSeconds: Math.round(process.uptime()),
      nodeVersion: process.version,
      platform: process.platform,
    },
    memory: {
      heapUsedBytes: Math.round(process.memoryUsage().heapUsed / 1024),
      heapTotalBytes: Math.round(process.memoryUsage().heapTotal / 1024),
      rssBytes: Math.round(process.memoryUsage().rss / 1024),
    },
    dependencies: {
      database: cfg.DB_DRIVER,
      redis: cfg.REDIS_URL ? 'configured' : 'not configured',
    },
    config: {
      jwtSecretLength: cfg.JWT_SECRET.length,
      rateLimitWindowMs: cfg.RATE_LIMIT_WINDOW_MS,
      rateLimitMax: cfg.RATE_LIMIT_MAX,
      corsOrigins: cfg.CORS_ORIGIN ?? 'none',
    },
  };

  res.setHeader('Content-Type', 'application/json');
  res.json(metrics);
}

import rateLimit from 'express-rate-limit';
import { cfg } from '../config/index.js';

// Rate limiters are keyed by client IP (behind a proxy the app trusts only when
// TRUST_PROXY is configured). Every limiter emits RFC-style `RateLimit-*`
// headers and a JSON body so clients can back off deterministically.
function clientKey(req: { ip?: string; socket?: { remoteAddress?: string } }): string {
  return req.ip ?? req.socket?.remoteAddress ?? 'unknown';
}

const baseOptions = {
  standardHeaders: true as const,
  legacyHeaders: false as const,
  keyGenerator: clientKey,
};

/** Applied to every request: a coarse floor against floods. */
export const globalLimiter = rateLimit({
  ...baseOptions,
  windowMs: cfg.RATE_LIMIT_WINDOW_MS,
  max: cfg.RATE_LIMIT_MAX,
  message: { error: 'too many requests, slow down' },
  skip: (req) =>
    req.path === '/api/health' ||
    req.path.startsWith('/api/health/') ||
    req.path === '/api/metrics' ||
    req.path === '/api/openapi.json' ||
    req.path.startsWith('/api/docs') ||
    req.path.startsWith('/socket.io'),
});

/** Brute-force protection for signup, login, verification and 2FA attempts. */
export const authLimiter = rateLimit({
  ...baseOptions,
  windowMs: cfg.RATE_LIMIT_WINDOW_MS,
  max: cfg.RATE_LIMIT_AUTH_MAX,
  message: { error: 'too many authentication attempts, slow down' },
});

/** Very strict limiter for endpoints that send email or check a password. */
export const sensitiveLimiter = rateLimit({
  ...baseOptions,
  windowMs: 15 * 60 * 1000,
  max: cfg.RATE_LIMIT_SENSITIVE_MAX,
  message: { error: 'too many attempts, try again later' },
});

/** Chat relay limiter so a single client cannot flood the socket relay. */
export const chatLimiter = rateLimit({
  ...baseOptions,
  windowMs: 60 * 1000,
  max: cfg.RATE_LIMIT_CHAT_PER_MIN,
  message: { error: 'message rate limit exceeded' },
});

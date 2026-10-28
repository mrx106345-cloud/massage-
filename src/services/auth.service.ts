import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import type { Request, Response, NextFunction } from 'express';
import { cfg } from '../config/index.js';
import { insertRow, selectOne, updateRows } from '../db/index.js';
import type { PublicUser } from '../db/types.js';
import { recordAudit, requestMeta } from './audit.service.js';
import { consumeBackupCode } from './backup-code.service.js';
import { cache } from './cache.js';
import { passwordChangedEmail, sendMail, verificationEmail } from './mailer.service.js';
import {
  createSession,
  findSessionByRefreshToken,
  revokeAllSessions,
  revokeSessionByToken,
  rotateSession,
} from './session.service.js';
import { issueToken } from './token.service.js';
import { verifyTotp } from './totp.service.js';

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// A fixed bcrypt hash verified for unknown emails so a failed login takes about
// the same time whether or not the address exists (limits enumeration by timing).
const DUMMY_PASSWORD_HASH = '$2a$12$R6JZismvFcfpIchJTLXUc.CTVY92fmubxqQLH402bwN.l4STs1836';

export interface AuthRequest {
  userId?: string;
  username?: string;
  tokenVersion?: number;
  user?: PublicUser;
}

type AuthExpressRequest = Request & AuthRequest;

const now = () => new Date().toISOString();

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Validation helpers
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

export function validateEmail(value: unknown): string | null {
  if (typeof value !== 'string' || !EMAIL_RE.test(value) || value.length > 255) return null;
  return value.trim().toLowerCase();
}

export function validatePassword(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (value.length < MIN_PASSWORD_LENGTH || value.length > MAX_PASSWORD_LENGTH) return null;
  return value;
}

export function validateUsername(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length < 3 || trimmed.length > 64) return null;
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) return null;
  return trimmed;
}

/** Strip secrets before a user object leaves the API. */
export function toPublicUser(row: Record<string, unknown>): PublicUser {
  return {
    id: String(row.id),
    username: String(row.username),
    email: String(row.email),
    avatar_url: row.avatar_url ? String(row.avatar_url) : null,
    is_online: Boolean(row.is_online),
    token_version: Number(row.token_version),
    email_verified: Boolean(row.email_verified),
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
  };
}

export async function findUserById(userId: string): Promise<Record<string, unknown> | null> {
  return selectOne('user', { id: userId });
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Endpoints
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

export async function signup(req: Request, res: Response) {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const email = validateEmail(body.email);
  const password = validatePassword(body.password);
  const username = validateUsername(body.username);

  if (!email || !password || !username) {
    if (!email) return res.status(400).json({ error: 'a valid email is required' });
    if (!password)
      return res.status(400).json({
        error: `password must be ${MIN_PASSWORD_LENGTH}-${MAX_PASSWORD_LENGTH} characters`,
      });
    return res
      .status(400)
      .json({ error: 'username must be 3-64 characters (letters, numbers, _ or -)' });
  }

  const existing = await selectOne('user', { _or: [{ username }, { email }] });
  if (existing) {
    return res.status(409).json({ error: 'that username or email is already taken' });
  }

  const id = randomUUID();
  const passwordHash = bcrypt.hashSync(password, 12);
  const created = now();

  await insertRow('user', {
    id,
    username,
    email,
    password_hash: passwordHash,
    avatar_url: null,
    token_version: 0,
    is_online: false,
    email_verified: false,
    totp_secret: null,
    totp_enabled: false,
    created_at: created,
    updated_at: created,
  });

  const user = (await findUserById(id)) ?? {
    id,
    username,
    email,
    avatar_url: null,
    is_online: false,
    token_version: 0,
    email_verified: false,
    created_at: created,
    updated_at: created,
  };

  const accessToken = signAccessToken(id, username, 0);
  const refresh = signRefreshToken(id);
  const meta = requestMeta(req);
  await createSession(id, refresh, 0, meta);

  // Verification email is best-effort: the account is usable already, and a
  // mail outage must not fail signup.
  const verification = await issueToken(
    id,
    'email_verification',
    cfg.EMAIL_VERIFICATION_TTL_HOURS * 3600,
  );
  await sendMail(verificationEmail(email, username, verification.token));
  await recordAudit({
    actorId: id,
    action: 'user.signup',
    targetType: 'user',
    targetId: id,
    ...meta,
  });

  res.status(201).json({
    token: accessToken,
    refreshToken: refresh,
    user: toPublicUser(user),
    emailVerificationRequired: cfg.REQUIRE_EMAIL_VERIFICATION,
  });
}

function lockoutKey(email: string): string {
  return `login:fail:${email}`;
}

async function registerFailedLogin(email: string, req: Request, reason: string) {
  const attempts = await cache.incr(lockoutKey(email), cfg.LOGIN_LOCKOUT_MINUTES * 60);
  await recordAudit({
    action: 'user.login_failed',
    targetType: 'email',
    metadata: { reason, attempts },
    ...requestMeta(req),
  });
  return attempts;
}

export async function login(req: Request, res: Response) {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const email = validateEmail(body.email);
  const password = body.password;
  const totpCode = typeof body.totpCode === 'string' ? body.totpCode : undefined;
  const backupCode = typeof body.backupCode === 'string' ? body.backupCode : undefined;

  if (!email) return res.status(400).json({ error: 'a valid email is required' });
  if (typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ error: 'password is required' });
  }

  const failures = Number((await cache.get(lockoutKey(email))) ?? 0);
  if (failures >= cfg.LOGIN_MAX_ATTEMPTS) {
    const retryAfter = await cache.ttl(lockoutKey(email));
    await recordAudit({
      action: 'user.login_locked',
      targetType: 'email',
      ...requestMeta(req),
    });
    res.setHeader('Retry-After', String(Math.max(retryAfter, 1)));
    return res.status(429).json({
      error: 'too many failed login attempts, try again later',
      retryAfterSeconds: Math.max(retryAfter, 1),
    });
  }

  const user = await selectOne('user', { email });
  if (!user) {
    await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
    await registerFailedLogin(email, req, 'unknown_email');
    return res.status(401).json({ error: 'invalid credentials' });
  }

  const passwordMatch = await bcrypt.compare(password, String(user.password_hash));
  if (!passwordMatch) {
    await registerFailedLogin(email, req, 'bad_password');
    return res.status(401).json({ error: 'invalid credentials' });
  }

  if (cfg.REQUIRE_EMAIL_VERIFICATION && !Boolean(user.email_verified)) {
    return res.status(403).json({ error: 'email verification required', code: 'email_unverified' });
  }

  if (Boolean(user.totp_enabled)) {
    const userId = String(user.id);
    if (backupCode) {
      const ok = await consumeBackupCode(userId, backupCode);
      if (!ok) {
        await registerFailedLogin(email, req, 'bad_backup_code');
        return res.status(401).json({ error: 'invalid two-factor code', code: 'totp_invalid' });
      }
    } else if (totpCode) {
      if (!verifyTotp(String(user.totp_secret ?? ''), totpCode)) {
        await registerFailedLogin(email, req, 'bad_totp');
        return res.status(401).json({ error: 'invalid two-factor code', code: 'totp_invalid' });
      }
    } else {
      return res.status(401).json({ error: 'two-factor code required', code: 'totp_required' });
    }
  }

  await cache.del(lockoutKey(email));

  const tokenVersion = Number(user.token_version);
  const accessToken = signAccessToken(String(user.id), String(user.username), tokenVersion);
  const refresh = signRefreshToken(String(user.id));
  const meta = requestMeta(req);
  await createSession(String(user.id), refresh, tokenVersion, meta);
  await recordAudit({
    actorId: String(user.id),
    action: 'user.login',
    targetType: 'user',
    targetId: String(user.id),
    ...meta,
  });

  res.json({ token: accessToken, refreshToken: refresh, user: toPublicUser(user) });
}

export async function requireAuth(req: AuthExpressRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing or malformed bearer token' });
  }

  let payload: jwt.JwtPayload;
  try {
    payload = verifyAccessToken(authHeader.slice(7));
  } catch {
    return res.status(401).json({ error: 'invalid or expired token' });
  }

  const userId = typeof payload.sub === 'string' ? payload.sub : null;
  if (!userId) return res.status(401).json({ error: 'invalid or expired token' });

  // Tokens are only valid while the user exists and their token version has not
  // been bumped (password change, logout-all, 2FA change, account deletion).
  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'invalid or expired token' });
  if (Number(user.token_version) !== Number(payload.tokenVersion)) {
    return res.status(401).json({ error: 'token has been revoked', code: 'token_revoked' });
  }

  req.userId = userId;
  req.username = typeof user.username === 'string' ? user.username : undefined;
  req.tokenVersion = Number(user.token_version);
  req.user = toPublicUser(user);
  next();
}

export async function refreshToken(req: Request, res: Response) {
  const token = (req.body as Record<string, unknown> | undefined)?.refreshToken;
  if (typeof token !== 'string' || token.length === 0) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }

  let subject: string;
  try {
    const payload = jwt.verify(token, cfg.JWT_SECRET) as jwt.JwtPayload;
    if (typeof payload.sub !== 'string') throw new Error('missing sub');
    subject = payload.sub;
  } catch {
    return res.status(401).json({ error: 'invalid or expired refresh token' });
  }

  // Refresh tokens are session-backed: revoked or rotated tokens are rejected.
  const session = await findSessionByRefreshToken(token);
  if (!session || session.userId !== subject) {
    return res.status(401).json({ error: 'refresh token has been revoked', code: 'token_revoked' });
  }

  const user = await findUserById(subject);
  if (!user) return res.status(401).json({ error: 'invalid or expired refresh token' });
  if (Number(user.token_version) !== session.tokenVersion) {
    await revokeAllSessions(subject);
    return res.status(401).json({ error: 'refresh token has been revoked', code: 'token_revoked' });
  }

  const nextRefresh = signRefreshToken(subject);
  await rotateSession(session.id, nextRefresh, session.tokenVersion);

  res.json({
    token: signAccessToken(subject, String(user.username), session.tokenVersion),
    refreshToken: nextRefresh,
  });
}

/** Revoke the presented refresh token. Safe to call repeatedly. */
export async function logout(req: Request, res: Response) {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const token = typeof body.refreshToken === 'string' ? body.refreshToken : '';
  const revoked = token ? await revokeSessionByToken(token) : false;
  const actorId = (req as AuthExpressRequest).userId ?? null;
  await recordAudit({
    actorId,
    action: 'user.logout',
    targetType: actorId ? 'user' : 'session',
    targetId: actorId ?? undefined,
    metadata: { revoked },
    ...requestMeta(req),
  });
  // Always 204: logout must not reveal whether a token was valid.
  res.status(204).end();
}

/** Change the password for the authenticated user and revoke every session. */
export async function changePassword(req: AuthExpressRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const body = (req.body ?? {}) as Record<string, unknown>;
  const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
  const newPassword = validatePassword(body.newPassword);
  if (!newPassword) {
    return res.status(400).json({
      error: `new password must be ${MIN_PASSWORD_LENGTH}-${MAX_PASSWORD_LENGTH} characters`,
    });
  }

  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  if (!(await bcrypt.compare(currentPassword, String(user.password_hash)))) {
    return res.status(401).json({ error: 'current password is incorrect' });
  }
  if (currentPassword === newPassword) {
    return res.status(400).json({ error: 'new password must differ from the current one' });
  }

  const nextVersion = Number(user.token_version) + 1;
  await updateRows(
    'user',
    { id: userId },
    {
      password_hash: bcrypt.hashSync(newPassword, 12),
      token_version: nextVersion,
      updated_at: now(),
    },
  );
  await revokeAllSessions(userId);
  await sendMail(passwordChangedEmail(String(user.email), String(user.username)));
  await recordAudit({
    actorId: userId,
    action: 'user.password_changed',
    targetType: 'user',
    targetId: userId,
    ...requestMeta(req),
  });

  res.json({ ok: true, reauthenticate: true });
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// JWT helpers
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

export function signAccessToken(userId: string, username: string, tokenVersion: number): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (jwt.sign as any)({ sub: userId, username, tokenVersion }, cfg.JWT_SECRET, {
    expiresIn: cfg.JWT_ACCESS_EXPIRES_IN,
    issuer: 'aegis-chat',
  });
}

export function signRefreshToken(userId: string): string {
  // `jti` guarantees rotation always yields a distinct token even within the
  // same second (JWT iat/exp only have second granularity), which is what makes
  // replay of a rotated token detectable.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (jwt.sign as any)({ sub: userId, typ: 'refresh', jti: randomUUID() }, cfg.JWT_SECRET, {
    expiresIn: cfg.JWT_REFRESH_EXPIRES_IN,
    issuer: 'aegis-chat',
  });
}

export function verifyAccessToken(token: string): jwt.JwtPayload {
  return jwt.verify(token, cfg.JWT_SECRET) as jwt.JwtPayload;
}

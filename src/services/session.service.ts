/**
 * Refresh-token session management.
 *
 * Each refresh token is stored as a SHA-256 hash in the `session` table. Rotating
 * a token replaces the stored hash, so a stolen refresh token is single-use and
 * replay of an old one can be detected (no active session matches it).
 */

import { createHash, randomUUID } from 'node:crypto';
import { cfg } from '../config/index.js';
import { deleteRows, insertRow, selectAll, selectOne, updateRows } from '../db/index.js';

export interface SessionMeta {
  ip?: string;
  userAgent?: string;
}

export interface SessionView {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  current: boolean;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function expiryFromNow(): string {
  return new Date(Date.now() + cfg.SESSION_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

export async function createSession(
  userId: string,
  refreshToken: string,
  tokenVersion: number,
  meta: SessionMeta = {},
): Promise<string> {
  const id = randomUUID();
  const now = new Date().toISOString();
  await insertRow('session', {
    id,
    user_id: userId,
    token: hashToken(refreshToken),
    token_version: tokenVersion,
    ip_address: meta.ip ?? null,
    user_agent: meta.userAgent ?? null,
    is_anonymous: false,
    created_at: now,
    updated_at: now,
    expires_at: expiryFromNow(),
    revoked_at: null,
  });
  return id;
}

export interface ActiveSession {
  id: string;
  userId: string;
  tokenVersion: number;
  expiresAt: string;
}

/** Find the session a refresh token belongs to, if it is still valid. */
export async function findSessionByRefreshToken(
  refreshToken: string,
): Promise<ActiveSession | null> {
  const row = await selectOne('session', {
    token: hashToken(refreshToken),
    revoked_at: { _isNull: true },
  });
  if (!row) return null;
  if (new Date(String(row.expires_at)).getTime() <= Date.now()) return null;
  return {
    id: String(row.id),
    userId: String(row.user_id),
    tokenVersion: Number(row.token_version),
    expiresAt: String(row.expires_at),
  };
}

/** Replace the stored refresh token (rotation) and extend the session. */
export async function rotateSession(
  sessionId: string,
  newRefreshToken: string,
  tokenVersion: number,
): Promise<void> {
  await updateRows(
    'session',
    { id: sessionId },
    {
      token: hashToken(newRefreshToken),
      token_version: tokenVersion,
      updated_at: new Date().toISOString(),
      expires_at: expiryFromNow(),
    },
  );
}

export async function revokeSessionByToken(refreshToken: string): Promise<boolean> {
  const row = await selectOne('session', {
    token: hashToken(refreshToken),
    revoked_at: { _isNull: true },
  });
  if (!row) return false;
  await updateRows(
    'session',
    { id: String(row.id) },
    { revoked_at: new Date().toISOString(), updated_at: new Date().toISOString() },
  );
  return true;
}

export async function revokeSessionById(userId: string, sessionId: string): Promise<boolean> {
  const row = await selectOne('session', { id: sessionId, user_id: userId });
  if (!row) return false;
  await updateRows(
    'session',
    { id: sessionId },
    { revoked_at: new Date().toISOString(), updated_at: new Date().toISOString() },
  );
  return true;
}

export async function revokeAllSessions(userId: string): Promise<number> {
  return updateRows(
    'session',
    { user_id: userId, revoked_at: { _isNull: true } },
    { revoked_at: new Date().toISOString(), updated_at: new Date().toISOString() },
  );
}

export async function listSessions(
  userId: string,
  currentRefreshToken?: string,
): Promise<SessionView[]> {
  const rows = await selectAll(
    'session',
    { user_id: userId, revoked_at: { _isNull: true } },
    100,
    ['id', 'ip_address', 'user_agent', 'created_at', 'updated_at', 'expires_at', 'token'],
    { column: 'created_at', direction: 'desc' },
  );
  const currentHash = currentRefreshToken ? hashToken(currentRefreshToken) : null;
  return rows.map((row) => ({
    id: String(row.id),
    ipAddress: row.ip_address ? String(row.ip_address) : null,
    userAgent: row.user_agent ? String(row.user_agent) : null,
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    expiresAt: String(row.expires_at),
    current: currentHash !== null && String(row.token) === currentHash,
  }));
}

/** Remove long-expired sessions (housekeeping). */
export async function purgeExpiredSessions(): Promise<void> {
  await deleteRows('session', { expires_at: { _lt: new Date().toISOString() } });
}

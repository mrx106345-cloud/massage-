/**
 * One-time auth tokens (email verification, password reset).
 *
 * Only a SHA-256 hash of the token is stored, so a database leak cannot be used
 * to verify an email or take over an account. Consumption is single-use and
 * enforced with a conditional UPDATE, which also makes concurrent redemptions
 * safe: only the first update matches `consumed_at IS NULL`.
 */

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { insertRow, selectOne, updateRows, deleteRows } from '../db/index.js';

export type AuthTokenType = 'email_verification' | 'password_reset';

export interface IssuedToken {
  token: string;
  expiresAt: string;
}

export function hashCode(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export async function issueToken(
  userId: string,
  type: AuthTokenType,
  ttlSeconds: number,
): Promise<IssuedToken> {
  // Invalidate any outstanding tokens of the same type so only the newest link
  // works (repeated "resend" clicks must not leave several live links).
  await deleteRows('auth_token', { user_id: userId, type });

  const token = randomBytes(32).toString('base64url');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();

  await insertRow('auth_token', {
    id: randomUUID(),
    user_id: userId,
    type,
    token_hash: hashCode(token),
    expires_at: expiresAt,
    consumed_at: null,
    created_at: now.toISOString(),
  });

  return { token, expiresAt };
}

export interface ConsumedToken {
  userId: string;
  tokenId: string;
}

/**
 * Redeem a token. Returns null when the token is unknown, already used, or
 * expired — callers must respond with the same generic error in all cases.
 */
export async function consumeToken(
  token: string,
  type: AuthTokenType,
): Promise<ConsumedToken | null> {
  if (!token || typeof token !== 'string') return null;
  const tokenHash = hashCode(token);
  const row = await selectOne('auth_token', { token_hash: tokenHash, type });
  if (!row) return null;
  if (row.consumed_at) return null;
  if (new Date(String(row.expires_at)).getTime() <= Date.now()) return null;

  const consumedAt = new Date().toISOString();
  const updated = await updateRows(
    'auth_token',
    { id: String(row.id), consumed_at: null },
    { consumed_at: consumedAt },
  );
  if (updated === 0) return null; // lost a race with another redemption

  return { userId: String(row.user_id), tokenId: String(row.id) };
}

/** Delete tokens that are expired or already redeemed. */
export async function purgeExpiredTokens(): Promise<void> {
  const now = new Date().toISOString();
  await deleteRows('auth_token', { expires_at: { _lt: now } });
  await deleteRows('auth_token', { consumed_at: { _notNull: true } });
}

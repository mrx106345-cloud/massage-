/**
 * Account lifecycle: email verification, password reset, 2FA enrolment,
 * session management, GDPR export and account deletion.
 *
 * Handlers follow the same (req, res) shape as the rest of the services so they
 * can be unit-tested without an HTTP server.
 */

import bcrypt from 'bcryptjs';
import type { Request, Response } from 'express';
import { cfg } from '../config/index.js';
import { deleteRows, selectAll, selectOne, updateRows } from '../db/index.js';
import { listAuditForUser, recordAudit, requestMeta } from './audit.service.js';
import type { AuthRequest } from './auth.service.js';
import { findUserById, toPublicUser, validateEmail, validatePassword } from './auth.service.js';
import {
  deleteBackupCodes,
  countUnusedBackupCodes,
  issueBackupCodes,
} from './backup-code.service.js';
import {
  passwordChangedEmail,
  passwordResetEmail,
  sendMail,
  verificationEmail,
} from './mailer.service.js';
import { deleteMediaObjectsForAccount } from './media.service.js';
import { listSessions, revokeAllSessions, revokeSessionById } from './session.service.js';
import { consumeToken, issueToken } from './token.service.js';
import { generateTotpSecret, otpauthUrl, verifyTotp } from './totp.service.js';

type AccountRequest = Request & AuthRequest;
const now = () => new Date().toISOString();

function bodyOf(req: AccountRequest): Record<string, unknown> {
  return (req.body ?? {}) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

export async function requestEmailVerification(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  if (Boolean(user.email_verified)) {
    return res.json({ ok: true, alreadyVerified: true });
  }

  const token = await issueToken(
    userId,
    'email_verification',
    cfg.EMAIL_VERIFICATION_TTL_HOURS * 3600,
  );
  await sendMail(verificationEmail(String(user.email), String(user.username), token.token));
  await recordAudit({
    actorId: userId,
    action: 'user.email_verification_sent',
    targetType: 'user',
    targetId: userId,
    ...requestMeta(req),
  });

  res.status(202).json({
    ok: true,
    expiresAt: token.expiresAt,
    expiresInHours: cfg.EMAIL_VERIFICATION_TTL_HOURS,
  });
}

export async function verifyEmail(req: AccountRequest, res: Response) {
  const token = bodyOf(req).token;
  if (typeof token !== 'string' || token.length === 0) {
    return res.status(400).json({ error: 'token is required' });
  }

  const consumed = await consumeToken(token, 'email_verification');
  if (!consumed) {
    return res.status(400).json({ error: 'invalid or expired verification token' });
  }

  const user = await findUserById(consumed.userId);
  if (!user) return res.status(400).json({ error: 'invalid or expired verification token' });

  await updateRows('user', { id: consumed.userId }, { email_verified: true, updated_at: now() });
  await recordAudit({
    actorId: consumed.userId,
    action: 'user.email_verified',
    targetType: 'user',
    targetId: consumed.userId,
    ...requestMeta(req),
  });

  res.json({ ok: true, emailVerified: true });
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

export async function requestPasswordReset(req: AccountRequest, res: Response) {
  const email = validateEmail(bodyOf(req).email);
  const generic = {
    ok: true,
    message: 'if that account exists, a password reset email has been sent',
  };

  // Always the same response: never disclose whether an address is registered.
  if (!email) return res.json(generic);

  const row = await selectOne('user', { email });
  if (!row) return res.json(generic);

  const userId = String(row.id);
  const token = await issueToken(userId, 'password_reset', cfg.PASSWORD_RESET_TTL_MINUTES * 60);
  await sendMail(passwordResetEmail(String(row.email), String(row.username), token.token));
  await recordAudit({
    actorId: null,
    action: 'user.password_reset_requested',
    targetType: 'user',
    targetId: userId,
    ...requestMeta(req),
  });

  res.json(generic);
}

export async function resetPassword(req: AccountRequest, res: Response) {
  const body = bodyOf(req);
  const token = body.token;
  const password = validatePassword(body.newPassword ?? body.password);
  if (typeof token !== 'string' || token.length === 0) {
    return res.status(400).json({ error: 'token is required' });
  }
  if (!password) {
    return res.status(400).json({ error: 'new password must be 8-128 characters' });
  }

  const consumed = await consumeToken(token, 'password_reset');
  if (!consumed) {
    return res.status(400).json({ error: 'invalid or expired reset token' });
  }

  const user = await findUserById(consumed.userId);
  if (!user) return res.status(400).json({ error: 'invalid or expired reset token' });

  await updateRows(
    'user',
    { id: consumed.userId },
    {
      password_hash: bcrypt.hashSync(password, 12),
      token_version: Number(user.token_version) + 1,
      updated_at: now(),
    },
  );
  await revokeAllSessions(consumed.userId);
  await sendMail(passwordChangedEmail(String(user.email), String(user.username)));
  await recordAudit({
    actorId: consumed.userId,
    action: 'user.password_reset',
    targetType: 'user',
    targetId: consumed.userId,
    ...requestMeta(req),
  });

  res.json({ ok: true, reauthenticate: true });
}

// ---------------------------------------------------------------------------
// TOTP two-factor authentication
// ---------------------------------------------------------------------------

export async function setupTotp(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  if (Boolean(user.totp_enabled)) {
    return res.status(409).json({ error: 'two-factor authentication is already enabled' });
  }

  const secret = generateTotpSecret();
  await updateRows(
    'user',
    { id: userId },
    { totp_secret: secret, totp_enabled: false, updated_at: now() },
  );

  res.json({
    secret,
    otpauthUrl: otpauthUrl(secret, String(user.email), cfg.TOTP_ISSUER),
    algorithm: 'SHA1',
    digits: 6,
    periodSeconds: 30,
  });
}

export async function enableTotp(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const code = bodyOf(req).code;

  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  if (!user.totp_secret) {
    return res
      .status(400)
      .json({ error: 'call /2fa/setup before enabling two-factor authentication' });
  }
  if (Boolean(user.totp_enabled)) {
    return res.status(409).json({ error: 'two-factor authentication is already enabled' });
  }
  if (typeof code !== 'string' || !verifyTotp(String(user.totp_secret), code)) {
    return res.status(400).json({ error: 'invalid two-factor code' });
  }

  await updateRows('user', { id: userId }, { totp_enabled: true, updated_at: now() });
  const backupCodes = await issueBackupCodes(userId);
  await recordAudit({
    actorId: userId,
    action: 'user.totp_enabled',
    targetType: 'user',
    targetId: userId,
    ...requestMeta(req),
  });

  res.json({
    ok: true,
    backupCodes,
    message: 'store these recovery codes securely; they are shown once',
  });
}

export async function disableTotp(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const password = bodyOf(req).password;
  if (typeof password !== 'string' || password.length === 0) {
    return res
      .status(400)
      .json({ error: 'password is required to disable two-factor authentication' });
  }

  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  if (!(await bcrypt.compare(password, String(user.password_hash)))) {
    return res.status(401).json({ error: 'password is incorrect' });
  }
  if (!Boolean(user.totp_enabled)) {
    return res.status(409).json({ error: 'two-factor authentication is not enabled' });
  }

  await updateRows(
    'user',
    { id: userId },
    { totp_enabled: false, totp_secret: null, updated_at: now() },
  );
  await deleteBackupCodes(userId);
  await recordAudit({
    actorId: userId,
    action: 'user.totp_disabled',
    targetType: 'user',
    targetId: userId,
    ...requestMeta(req),
  });

  res.json({ ok: true });
}

export async function totpStatus(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  res.json({
    enabled: Boolean(user.totp_enabled),
    pendingSetup: Boolean(user.totp_secret) && !Boolean(user.totp_enabled),
    unusedBackupCodes: await countUnusedBackupCodes(userId),
  });
}

// ---------------------------------------------------------------------------
// Sessions & logout
// ---------------------------------------------------------------------------

export async function listUserSessions(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const headerToken = req.headers?.['x-refresh-token'];
  const current = typeof headerToken === 'string' ? headerToken : undefined;
  res.json({ sessions: await listSessions(userId, current) });
}

export async function revokeUserSession(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const sessionId = (req.params as Record<string, string> | undefined)?.sessionId;
  if (!sessionId) return res.status(400).json({ error: 'sessionId is required' });

  const revoked = await revokeSessionById(userId, sessionId);
  if (!revoked) return res.status(404).json({ error: 'session not found' });
  await recordAudit({
    actorId: userId,
    action: 'user.session_revoked',
    targetType: 'session',
    targetId: sessionId,
    ...requestMeta(req),
  });
  res.json({ ok: true });
}

export async function logoutAllSessions(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  // Bumping token_version invalidates every outstanding access token.
  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  await updateRows(
    'user',
    { id: userId },
    { token_version: Number(user.token_version) + 1, updated_at: now() },
  );
  await revokeAllSessions(userId);
  await recordAudit({
    actorId: userId,
    action: 'user.logout_all',
    targetType: 'user',
    targetId: userId,
    ...requestMeta(req),
  });
  res.status(204).end();
}

// ---------------------------------------------------------------------------
// GDPR: export & deletion
// ---------------------------------------------------------------------------

export async function exportAccount(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });

  const membershipRows = await selectAll('group_member', { user_id: userId }, 1000);
  const groupIds = membershipRows.map((row) => String(row.group_id)).filter(Boolean);
  const groups =
    groupIds.length > 0 ? await selectAll('group', { id: { _in: groupIds } }, 1000) : [];
  const messages = await selectAll('message', { sender_id: userId }, 5000);
  const media = await selectAll('media_file', { owner_id: userId }, 5000);
  const sessions = await listSessions(userId);
  const audit = await listAuditForUser(userId, 200);

  await recordAudit({
    actorId: userId,
    action: 'user.exported',
    targetType: 'user',
    targetId: userId,
    ...requestMeta(req),
  });

  res.setHeader(
    'Content-Disposition',
    `attachment; filename="aegis-export-${new Date().toISOString().slice(0, 10)}.json"`,
  );
  res.json({
    exportedAt: new Date().toISOString(),
    user: toPublicUser(user),
    groups,
    memberships: membershipRows,
    messages,
    media,
    sessions,
    audit,
  });
}

export async function deleteAccount(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const password = bodyOf(req).password;
  if (typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ error: 'password is required to delete your account' });
  }

  const user = await findUserById(userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  if (!(await bcrypt.compare(password, String(user.password_hash)))) {
    return res.status(401).json({ error: 'password is incorrect' });
  }

  await recordAudit({
    actorId: userId,
    action: 'user.deleted',
    targetType: 'user',
    targetId: userId,
    metadata: { username: String(user.username) },
    ...requestMeta(req),
  });

  // Remove encrypted media objects before their database rows disappear; the
  // storage key lives on the row, so deletion must happen first.
  await deleteMediaObjectsForAccount(userId);

  // Personal data is removed; the audit trail is retained (anonymised) so
  // security events remain reviewable.
  await Promise.all([
    deleteRows('session', { user_id: userId }),
    deleteRows('auth_token', { user_id: userId }),
    deleteRows('totp_backup_code', { user_id: userId }),
    deleteRows('offline_queue_item', { user_id: userId }),
    deleteRows('group_member', { user_id: userId }),
    deleteRows('media_file', { owner_id: userId }),
    deleteRows('message', { sender_id: userId }),
    deleteRows('direct_message_thread', { _or: [{ user_a_id: userId }, { user_b_id: userId }] }),
    deleteRows('invite', { inviter_id: userId }),
    deleteRows('invite', { invited_email: String(user.email) }),
    deleteRows('crypto_key', { owner_id: userId }),
    deleteRows('report', {
      _or: [{ reported_by_id: userId }, { reported_user_id: userId }],
    }),
    updateRows('audit_log', { actor_id: userId }, { actor_id: null }),
  ]);
  await deleteRows('user', { id: userId });

  res.status(204).end();
}

export async function listAuditTrail(req: AccountRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const limitRaw = (req.query as Record<string, unknown> | undefined)?.limit;
  const limit = Number(limitRaw ?? 50);
  res.json({ entries: await listAuditForUser(userId, Number.isFinite(limit) ? limit : 50) });
}

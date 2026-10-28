/**
 * Security audit trail.
 *
 * Every authentication / account-lifecycle event is appended to `audit_log`.
 * Writes are best-effort: an audit failure must not break the user's request,
 * but it is logged loudly so it can be alerted on.
 */

import { randomUUID } from 'node:crypto';
import { insertRow, selectAll } from '../db/index.js';
import { logger } from '../utils/logger.js';

export type AuditAction =
  | 'user.signup'
  | 'user.login'
  | 'user.login_failed'
  | 'user.login_locked'
  | 'user.logout'
  | 'user.logout_all'
  | 'user.email_verified'
  | 'user.email_verification_sent'
  | 'user.password_reset_requested'
  | 'user.password_reset'
  | 'user.password_changed'
  | 'user.totp_enabled'
  | 'user.totp_disabled'
  | 'user.session_revoked'
  | 'user.exported'
  | 'user.deleted';

export interface AuditEvent {
  actorId?: string | null;
  action: AuditAction;
  targetType?: string;
  targetId?: string;
  ip?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditEntry {
  id: string;
  actorId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

const MAX_METADATA_LENGTH = 2000;

export async function recordAudit(event: AuditEvent): Promise<void> {
  try {
    let metadata: string | null = null;
    if (event.metadata) {
      const serialized = JSON.stringify(event.metadata);
      metadata =
        serialized.length > MAX_METADATA_LENGTH
          ? serialized.slice(0, MAX_METADATA_LENGTH)
          : serialized;
    }
    await insertRow('audit_log', {
      id: randomUUID(),
      actor_id: event.actorId ?? null,
      action: event.action,
      target_type: event.targetType ?? null,
      target_id: event.targetId ?? null,
      ip_address: event.ip ?? null,
      user_agent: event.userAgent ?? null,
      metadata,
      created_at: new Date().toISOString(),
    });
  } catch (error) {
    logger.error(
      { action: event.action, err: error instanceof Error ? error.message : String(error) },
      'failed to write audit log entry',
    );
  }
}

function toEntry(row: Record<string, unknown>): AuditEntry {
  let metadata: Record<string, unknown> | null = null;
  if (typeof row.metadata === 'string' && row.metadata.length > 0) {
    try {
      metadata = JSON.parse(row.metadata) as Record<string, unknown>;
    } catch {
      metadata = { raw: row.metadata };
    }
  }
  return {
    id: String(row.id),
    actorId: row.actor_id ? String(row.actor_id) : null,
    action: String(row.action),
    targetType: row.target_type ? String(row.target_type) : null,
    targetId: row.target_id ? String(row.target_id) : null,
    ipAddress: row.ip_address ? String(row.ip_address) : null,
    userAgent: row.user_agent ? String(row.user_agent) : null,
    metadata,
    createdAt: String(row.created_at),
  };
}

/** Audit entries where the user is either the actor or the target. */
export async function listAuditForUser(userId: string, limit = 50): Promise<AuditEntry[]> {
  const rows = await selectAll(
    'audit_log',
    { _or: [{ actor_id: userId }, { target_id: userId }] },
    Math.min(Math.max(limit, 1), 200),
    [],
    { column: 'created_at', direction: 'desc' },
  );
  return rows.map(toEntry);
}

/** Helper for extracting request metadata without tying services to Express. */
export function requestMeta(req: {
  ip?: string;
  socket?: { remoteAddress?: string };
  headers?: Record<string, unknown>;
}) {
  return {
    ip: req.ip ?? req.socket?.remoteAddress ?? undefined,
    userAgent:
      typeof req.headers?.['user-agent'] === 'string'
        ? (req.headers['user-agent'] as string)
        : undefined,
  };
}

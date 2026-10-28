import { countRows, insertRow, selectAll, selectOne, updateRows } from '../db/index.js';
import type { Request, Response } from 'express';

export interface ThreadRequest extends Request {
  userId?: string;
}

export interface ThreadMessageDto {
  id: string;
  threadId: string;
  senderId: string;
  parentId: string | null;
  type: string;
  cipherBundle: unknown;
  metadata: unknown;
  signature: string | null;
  signatureKeyId: string | null;
  status: string;
  createdAt: string;
}

export interface ThreadSummary {
  id: string;
  type: 'direct' | 'group';
  participant?: {
    id: string;
    username: string;
    avatarUrl: string | null;
    isOnline: boolean;
  } | null;
  group?: {
    id: string;
    name: string | null;
    isPrivate: boolean;
    gmVersion: number;
  };
  lastMessage: ThreadMessageDto | null;
  unreadCount: number;
  lastUpdatedAt: string | null;
}

const DIRECT_PREFIX = 'thread_direct_';

export function directThreadId(a: string, b: string): string {
  return `${DIRECT_PREFIX}${[a, b].sort().join('__')}`;
}

function asText(value: unknown): string {
  return typeof value === 'string'
    ? value
    : value === null || value === undefined
      ? ''
      : String(value);
}

function asNullableText(value: unknown): string | null {
  return value === null || value === undefined ? null : asText(value);
}

function parseJsonColumn(value: unknown): unknown {
  if (typeof value !== 'string' || value.length === 0) return null;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

/** Shape a stored message row into the DTO returned by the HTTP API. */
function toMessageDto(row: Record<string, unknown>): ThreadMessageDto {
  return {
    id: asText(row.id),
    threadId: asText(row.thread_id),
    senderId: asText(row.sender_id),
    parentId: asNullableText(row.parent_id),
    type: asText(row.content_type),
    cipherBundle: parseJsonColumn(row.encrypted_content),
    metadata: parseJsonColumn(row.metadata),
    signature: asNullableText(row.signature),
    signatureKeyId: asNullableText(row.signature_key_id),
    status: asText(row.status),
    createdAt: asText(row.created_at),
  };
}

/** The two user ids encoded in a 1-to-1 thread id, or null if it is malformed. */
export function parseDirectThreadId(threadId: string): [string, string] | null {
  if (!threadId.startsWith(DIRECT_PREFIX)) return null;
  const parts = threadId.slice(DIRECT_PREFIX.length).split('__');
  if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) return null;
  if (parts[0] === parts[1]) return null;
  return [parts[0], parts[1]];
}

/**
 * Ensure a direct message thread record exists and update last message info.
 */
export async function touchDirectThread(
  senderId: string,
  recipientId: string,
  messageId: string,
  createdAt: string,
): Promise<string> {
  const [userA, userB] = [senderId, recipientId].sort();
  const threadId = directThreadId(senderId, recipientId);

  const existing = await selectOne('direct_message_thread', { id: threadId });
  if (!existing) {
    await insertRow('direct_message_thread', {
      id: threadId,
      user_a_id: userA,
      user_b_id: userB,
      last_message_id: messageId,
      last_read_message_id: null,
      last_read_at: null,
      last_updated_at: createdAt,
      unread_count_a: senderId === userB ? 1 : 0,
      unread_count_b: senderId === userA ? 1 : 0,
      created_at: createdAt,
      updated_at: createdAt,
    });
  } else {
    const isSenderA = senderId === userA;
    await updateRows(
      'direct_message_thread',
      { id: threadId },
      {
        last_message_id: messageId,
        last_updated_at: createdAt,
        unread_count_a: isSenderA
          ? Number(existing.unread_count_a ?? 0)
          : Number(existing.unread_count_a ?? 0) + 1,
        unread_count_b: isSenderA
          ? Number(existing.unread_count_b ?? 0) + 1
          : Number(existing.unread_count_b ?? 0),
        updated_at: createdAt,
      },
    );
  }

  return threadId;
}

/**
 * List all active conversations (both 1-to-1 DMs and joined group chats),
 * newest activity first.
 */
export async function listThreads(req: ThreadRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const [asA, asB] = await Promise.all([
    selectAll('direct_message_thread', { user_a_id: userId }, 200),
    selectAll('direct_message_thread', { user_b_id: userId }, 200),
  ]);

  const threads: ThreadSummary[] = [];

  for (const thread of [...asA, ...asB]) {
    const isUserA = asText(thread.user_a_id) === userId;
    const peerId = isUserA ? asText(thread.user_b_id) : asText(thread.user_a_id);
    const peer = await selectOne('user', { id: peerId }, [
      'id',
      'username',
      'avatar_url',
      'is_online',
    ]);

    let lastMessage: ThreadMessageDto | null = null;
    if (thread.last_message_id) {
      const row = await selectOne('message', { id: thread.last_message_id }, [
        'id',
        'thread_id',
        'sender_id',
        'parent_id',
        'content_type',
        'encrypted_content',
        'metadata',
        'signature',
        'signature_key_id',
        'status',
        'created_at',
      ]);
      if (row) lastMessage = toMessageDto(row);
    }

    threads.push({
      id: asText(thread.id),
      type: 'direct',
      participant: peer
        ? {
            id: asText(peer.id),
            username: asText(peer.username),
            avatarUrl: asNullableText(peer.avatar_url),
            isOnline: Boolean(peer.is_online),
          }
        : null,
      lastMessage,
      unreadCount: isUserA
        ? Number(thread.unread_count_a ?? 0)
        : Number(thread.unread_count_b ?? 0),
      lastUpdatedAt: asNullableText(thread.last_updated_at) ?? asNullableText(thread.updated_at),
    });
  }

  const groupMemberships = await selectAll(
    'group_member',
    { user_id: userId, status: 'active' },
    200,
  );
  for (const membership of groupMemberships) {
    const groupId = asText(membership.group_id);
    const group = await selectOne('group', { id: groupId }, [
      'id',
      'name',
      'is_private',
      'gm_version',
      'created_at',
    ]);
    if (!group) continue;

    const latestRows = await selectAll(
      'message',
      { thread_id: groupId },
      1,
      [
        'id',
        'thread_id',
        'sender_id',
        'parent_id',
        'content_type',
        'encrypted_content',
        'metadata',
        'signature',
        'signature_key_id',
        'status',
        'created_at',
      ],
      { column: 'created_at', direction: 'desc' },
    );
    const lastMessage = latestRows[0] ? toMessageDto(latestRows[0]) : null;

    // Group unread is measured from the member's own read cursor so one member
    // reading a conversation never clears another member's badge.
    const lastReadAt = asNullableText(membership.last_read_at);
    const unreadCount = lastReadAt
      ? await countRows('message', {
          thread_id: groupId,
          created_at: { _gt: lastReadAt },
          sender_id: { _ne: userId },
        })
      : await countRows('message', { thread_id: groupId, sender_id: { _ne: userId } });

    threads.push({
      id: groupId,
      type: 'group',
      group: {
        id: groupId,
        name: asNullableText(group.name),
        isPrivate: Boolean(group.is_private),
        gmVersion: Number(group.gm_version ?? 0),
      },
      lastMessage,
      unreadCount,
      lastUpdatedAt: lastMessage?.createdAt ?? asNullableText(group.created_at),
    });
  }

  threads.sort((a, b) =>
    String(b.lastUpdatedAt ?? '').localeCompare(String(a.lastUpdatedAt ?? '')),
  );

  res.json({ threads });
}

/**
 * Verify the caller may read a thread, returning an error message when not.
 */
export async function assertThreadAccess(
  threadId: string,
  userId: string,
): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  if (threadId.startsWith(DIRECT_PREFIX)) {
    const participants = parseDirectThreadId(threadId);
    if (!participants) {
      return { ok: false, status: 400, error: 'malformed direct thread id' };
    }
    if (!participants.includes(userId)) {
      return { ok: false, status: 403, error: 'not a participant of this conversation' };
    }
    return { ok: true };
  }

  const member = await selectOne('group_member', {
    group_id: threadId,
    user_id: userId,
    status: 'active',
  });
  if (!member) {
    return { ok: false, status: 403, error: 'not a member of this group' };
  }
  return { ok: true };
}

/**
 * Clear the caller's unread counter for a thread. Read state is per participant
 * for 1-to-1 threads and per member for groups.
 */
export async function markThreadRead(req: ThreadRequest, res: Response) {
  const { threadId } = req.params as { threadId: string };
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const access = await assertThreadAccess(threadId, userId);
  if (!access.ok) return res.status(access.status).json({ error: access.error });

  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

  if (threadId.startsWith(DIRECT_PREFIX)) {
    const row = await selectOne('direct_message_thread', { id: threadId });
    if (row) {
      const isUserA = String(row.user_a_id) === userId;
      await updateRows(
        'direct_message_thread',
        { id: threadId },
        isUserA
          ? { unread_count_a: 0, last_read_at: timestamp, updated_at: timestamp }
          : { unread_count_b: 0, last_read_at: timestamp, updated_at: timestamp },
      );
    }
  } else {
    await updateRows(
      'group_member',
      { group_id: threadId, user_id: userId },
      { last_read_at: timestamp },
    );
  }

  return res.json({ ok: true, threadId, readAt: timestamp });
}

/**
 * Fetch paginated message history for a conversation thread.
 *
 * Newest first, cursor-paginated with `before=<created_at>`. Ciphertext is
 * returned verbatim: only the sender's device and the recipients hold keys.
 */
export async function getThreadMessages(req: ThreadRequest, res: Response) {
  const { threadId } = req.params as { threadId: string };
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const access = await assertThreadAccess(threadId, userId);
  if (!access.ok) return res.status(access.status).json({ error: access.error });

  const rawLimit = Number(req.query.limit ?? 50);
  const limit = Math.min(Math.max(1, Number.isFinite(rawLimit) ? Math.floor(rawLimit) : 50), 100);
  const before = typeof req.query.before === 'string' ? req.query.before.trim() : '';
  if (before && Number.isNaN(Date.parse(before))) {
    return res.status(400).json({ error: 'before must be an ISO-8601 timestamp' });
  }

  const where: Record<string, unknown> = { thread_id: threadId };
  if (before) where.created_at = { _lt: before };

  const rows = await selectAll(
    'message',
    where,
    limit,
    [
      'id',
      'thread_id',
      'sender_id',
      'parent_id',
      'content_type',
      'encrypted_content',
      'metadata',
      'signature',
      'signature_key_id',
      'status',
      'created_at',
    ],
    { column: 'created_at', direction: 'desc' },
  );

  const hasMore = rows.length === limit;
  res.json({
    threadId,
    messages: rows.map(toMessageDto),
    hasMore,
    nextCursor: hasMore ? (rows[rows.length - 1]?.created_at ?? null) : null,
  });
}

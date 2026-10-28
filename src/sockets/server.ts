// src/sockets/server.ts — E2EE relay layer. Clients keep the keys; the server
// only validates, persists opaque envelopes and fans them out. Plaintext is
// never accepted over the socket.

import { randomUUID } from 'node:crypto';
import { deleteRows, insertRow, selectAll, selectOne, updateRows } from '../db/index.js';
import { verifyAccessToken } from '../services/auth.service.js';
import {
  groupKeySigningPayload,
  messageSigningPayload,
  verifyEd25519Signature,
} from '../services/crypto.service.js';
import { deleteMediaObjectsForMessage } from '../services/media.service.js';
import { touchDirectThread } from '../services/threads.service.js';
import type { SocketContext } from './types.js';
import type { Socket } from 'socket.io';

const CONTENT_TYPES = new Set(['text', 'image', 'video', 'audio', 'file']);
const MAX_SOCKET_PAYLOAD_BYTES = 128 * 1024;
const MAX_CIPHERTEXT_CHARS = 120 * 1024;
const MAX_METADATA_BYTES = 32 * 1024;
const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;
const SOCKET_EVENT_WINDOW_MS = 10_000;
const SOCKET_EVENT_LIMIT = 60;

interface SocketData {
  userId?: string;
  username?: string;
  tokenVersion?: number;
  rate?: { tokens: number; last: number };
}

const now = () => new Date().toISOString().replace(/\.\\d{3}Z$/, 'Z');

const asString = (value: unknown): string | undefined =>
  typeof value === 'string' && value.length > 0 ? value : undefined;

const emitError = (socket: Socket, code: string, message: string) =>
  socket.emit('receive_message', { error: message, code });

function payloadTooLarge(payload: unknown): boolean {
  try {
    return Buffer.byteLength(JSON.stringify(payload ?? null), 'utf8') > MAX_SOCKET_PAYLOAD_BYTES;
  } catch {
    return true;
  }
}

/** Per-socket token bucket across all socket events. */
function consumeSocketToken(socket: Socket, cost = 1): boolean {
  const data = socket.data as SocketData;
  const nowMs = Date.now();
  const bucket = data.rate ?? { tokens: SOCKET_EVENT_LIMIT, last: nowMs };
  const elapsed = Math.max(0, nowMs - bucket.last);
  bucket.tokens = Math.min(
    SOCKET_EVENT_LIMIT,
    bucket.tokens + (elapsed / SOCKET_EVENT_WINDOW_MS) * SOCKET_EVENT_LIMIT,
  );
  bucket.last = nowMs;
  if (bucket.tokens < cost) {
    data.rate = bucket;
    return false;
  }
  bucket.tokens -= cost;
  data.rate = bucket;
  return true;
}

function validIsoTimestamp(value: string): boolean {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && Math.abs(Date.now() - parsed) <= MAX_CLOCK_SKEW_MS;
}

async function activeSigningKey(
  userId: string,
): Promise<{ keyId: string; publicKeyHex: string } | null> {
  const rows = await selectAll(
    'crypto_key',
    { owner_id: userId, status: 'active', ed25519_public: { _notNull: true } },
    1,
    ['key_id', 'ed25519_public', 'created_at'],
    { column: 'created_at', direction: 'desc' },
  );
  const row = rows[0];
  if (!row || typeof row.ed25519_public !== 'string') return null;
  if (!/^[0-9a-f]{64}$/i.test(row.ed25519_public)) return null;
  return { keyId: String(row.key_id), publicKeyHex: row.ed25519_public };
}

/** Latest X25519 identity key per active group member, keyed by key id. */
async function activeGroupMemberKeys(groupId: string): Promise<{
  memberIds: string[];
  keyToUser: Map<string, string>;
  userToKey: Map<string, string>;
}> {
  const members = await selectAll('group_member', { group_id: groupId, status: 'active' }, 2000, [
    'user_id',
  ]);
  const memberIds = [...new Set(members.map((row) => String(row.user_id)))];
  const keyToUser = new Map<string, string>();
  const userToKey = new Map<string, string>();
  if (memberIds.length === 0) return { memberIds, keyToUser, userToKey };

  const keys = await selectAll(
    'crypto_key',
    { owner_id: { _in: memberIds }, status: 'active', x25519_public: { _notNull: true } },
    5000,
    ['owner_id', 'key_id', 'x25519_public', 'created_at'],
    { column: 'created_at', direction: 'desc' },
  );
  for (const key of keys) {
    const userId = String(key.owner_id);
    if (userToKey.has(userId)) continue;
    const keyId = String(key.key_id);
    userToKey.set(userId, keyId);
    keyToUser.set(keyId, userId);
  }
  return { memberIds, keyToUser, userToKey };
}

function _parseJsonColumn(value: unknown): unknown {
  if (typeof value !== 'string' || value.length === 0) return null;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function directThreadId(a: string, b: string): string {
  return `thread_direct_${[a, b].sort().join('__')}`;
}

function parseDirectThreadId(threadId: string): [string, string] | null {
  const prefix = 'thread_direct_';
  if (!threadId.startsWith(prefix)) return null;
  const parts = threadId.slice(prefix.length).split('__');
  if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) return null;
  if (parts[0] === parts[1]) return null;
  return [parts[0], parts[1]];
}

function normalizeBundle(bundle: unknown): Record<string, unknown> | null {
  if (!bundle || typeof bundle !== 'object') return null;
  const b = bundle as Record<string, unknown>;
  if (typeof b.ciphertext !== 'string' || b.ciphertext.length === 0) return null;
  return {
    ...b,
    iv: typeof b.iv === 'string' ? b.iv : undefined,
    alg: typeof b.alg === 'string' ? b.alg : 'aes-256-gcm',
    keyId: typeof b.keyId === 'string' ? b.keyId : undefined,
    recipientKeyId: typeof b.recipientKeyId === 'string' ? b.recipientKeyId : undefined,
    delivery_receipts: Array.isArray(b.delivery_receipts) ? b.delivery_receipts : undefined,
    ephemeralPublicKey: typeof b.ephemeralPublicKey === 'string' ? b.ephemeralPublicKey : undefined,
    gmkId: typeof b.gmkId === 'string' ? b.gmkId : undefined,
    status: typeof b.status === 'string' ? b.status : undefined,
    sessionId: typeof b.sessionId === 'string' ? b.sessionId : undefined,
    messageId: typeof b.messageId === 'string' ? b.messageId : undefined,
  } as Record<string, unknown>;
}

export function createSocketServer(ctx: SocketContext) {
  const { io, users } = ctx;

  io.use(async (socket, next) => {
    const token =
      socket.handshake.auth?.token ??
      socket.handshake.headers?.authorization?.replace(/^Bearer\s+/i, '');
    if (!token) return next(new Error('missing token'));

    try {
      const payload = verifyAccessToken(token);
      const userId = typeof payload.sub === 'string' ? payload.sub : undefined;
      if (!userId) throw new Error('missing sub');

      const user = await selectOne('user', { id: userId }, ['id', 'username', 'token_version']);
      if (!user || Number(user.token_version) !== Number(payload.tokenVersion)) {
        throw new Error('revoked token');
      }

      const data = socket.data as SocketData;
      data.userId = userId;
      data.username = typeof user.username === 'string' ? user.username : undefined;
      data.tokenVersion = Number(user.token_version);
      next();
    } catch {
      next(new Error('invalid or expired token'));
    }
  });

  io.on('connection', (socket) => {
    const data = socket.data as SocketData;
    const userId = data.userId;
    if (!userId) {
      socket.disconnect(true);
      return;
    }

    data.rate = { tokens: SOCKET_EVENT_LIMIT, last: Date.now() };

    const currentSet = users.get(userId);
    const isFirstConnection = !currentSet || currentSet.size === 0;
    if (!currentSet) users.set(userId, new Set());
    users.get(userId)!.add(socket);

    if (isFirstConnection) {
      void updateRows('user', { id: userId }, { is_online: true, updated_at: now() }).catch(
        () => {},
      );
      io.emit('user_status', { userId, isOnline: true });
    }

    void (async () => {
      try {
        await flushUserOfflineQueue(userId, users);
      } catch (err) {
        console.error('[offline-queue] user flush failed:', err);
      }
    })();

    socket.on('disconnect', () => {
      const sockets = users.get(userId);
      if (sockets) sockets.delete(socket);
      if (!sockets || sockets.size === 0) {
        users.delete(userId);
        void updateRows('user', { id: userId }, { is_online: false, updated_at: now() }).catch(
          () => {},
        );
        io.emit('user_status', { userId, isOnline: false });
      }
    });

    socket.on('join_room', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }
      const body = (payload ?? {}) as Record<string, unknown>;
      const threadId = asString(body.threadId);
      const groupId = asString(body.groupId);

      if (threadId) socket.join(`thread:${threadId}`);
      if (groupId) {
        const membership = await selectOne('group_member', { group_id: groupId, user_id: userId });
        if (!membership) return emitError(socket, 'forbidden', 'not a member of this group');
        socket.join(`group:${groupId}`);
      }
      socket.emit('room_joined', { ok: true, room: threadId ?? groupId });
    });

    socket.on('send_message', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }

      const body = (payload ?? {}) as Record<string, unknown>;
      const recipientId = asString(body.recipientId);
      const groupId = asString(body.groupId);
      const bundle = normalizeBundle(body.cipherBundle);
      const messageId = asString(body.messageId);
      const createdAt = asString(body.createdAt);
      const signature = asString(body.signature);

      if (!groupId && !recipientId) {
        return emitError(socket, 'invalid_request', 'missing recipientId or groupId');
      }
      if (recipientId && recipientId === userId) {
        return emitError(socket, 'invalid_request', 'cannot send a direct message to yourself');
      }
      if (!bundle) {
        return emitError(
          socket,
          'encryption_required',
          'send_message requires an encrypted cipherBundle; plaintext is not accepted',
        );
      }
      const ciphertext = bundle.ciphertext as string;
      if (typeof ciphertext !== 'string' || ciphertext.length > MAX_CIPHERTEXT_CHARS) {
        return emitError(socket, 'payload_too_large', 'ciphertext exceeds the maximum size');
      }
      if (!messageId || !/^[A-Za-z0-9_-]{8,64}$/.test(messageId)) {
        return emitError(socket, 'invalid_request', 'messageId must be an 8-64 character id');
      }
      if (!createdAt || !validIsoTimestamp(createdAt)) {
        return emitError(
          socket,
          'invalid_request',
          'createdAt must be an ISO timestamp within ten minutes of server time',
        );
      }
      const rawType = body.type === undefined ? 'text' : String(body.type);
      if (!CONTENT_TYPES.has(rawType)) {
        return emitError(socket, 'invalid_request', 'unsupported content type');
      }
      const type = rawType;
      const parentId = asString(body.parentId);
      const metadataValue = body.metadata === undefined ? null : body.metadata;
      if (
        metadataValue !== null &&
        (typeof metadataValue !== 'object' || Array.isArray(metadataValue))
      ) {
        return emitError(socket, 'invalid_request', 'metadata must be an object');
      }
      let metadata: string | null = null;
      try {
        metadata = metadataValue === null ? null : JSON.stringify(metadataValue);
      } catch {
        return emitError(socket, 'invalid_request', 'metadata is not serializable');
      }
      if (metadata && Buffer.byteLength(metadata, 'utf8') > MAX_METADATA_BYTES) {
        return emitError(socket, 'payload_too_large', 'metadata exceeds the maximum size');
      }

      let threadId: string;
      if (groupId) {
        const membership = await selectOne('group_member', {
          group_id: groupId,
          user_id: userId,
          status: 'active',
        });
        if (!membership) return emitError(socket, 'forbidden', 'not a member of this group');
        threadId = groupId;
      } else {
        const recipient = await selectOne('user', { id: recipientId }, ['id']);
        if (!recipient) return emitError(socket, 'not_found', 'recipient not found');
        threadId = directThreadId(userId, recipientId!);
      }

      // Authorisation comes before cryptography: an outsider must not learn
      // anything about signing keys or signature validity.
      if (!signature) {
        return emitError(socket, 'signature_required', 'messages must be signed by the sender');
      }

      const signingKey = await activeSigningKey(userId);
      if (!signingKey) {
        return emitError(
          socket,
          'signing_key_required',
          'publish an Ed25519 signing key before sending messages',
        );
      }
      const signedPayload = messageSigningPayload({
        messageId,
        threadId,
        senderId: userId,
        type,
        createdAt,
        cipherBundle: bundle,
        metadata: metadataValue as Record<string, unknown> | null,
      });
      if (!verifyEd25519Signature(signedPayload, signature, signingKey.publicKeyHex)) {
        return emitError(socket, 'invalid_signature', 'message signature is invalid');
      }

      const existing = await selectOne('message', { id: messageId }, ['id']);
      if (existing) {
        return emitError(socket, 'duplicate_message', 'a message with that id already exists');
      }

      await insertRow('message', {
        id: messageId,
        thread_id: threadId,
        sender_id: userId,
        parent_id: parentId ?? null,
        content_type: type,
        content: null,
        encrypted_content: JSON.stringify(bundle),
        encryption_alg: bundle.alg ?? 'aes-256-gcm',
        encryption_key_id: bundle.keyId ?? null,
        gmk_id: bundle.gmkId ?? null,
        metadata,
        signature,
        signature_key_id: signingKey.keyId,
        status: 'sent',
        delivery_receipts: null,
        created_at: createdAt,
        updated_at: createdAt,
      });

      const relayed = {
        messageId,
        senderId: userId,
        threadId,
        type,
        cipherBundle: bundle,
        metadata: metadataValue ?? null,
        signature,
        signatureKeyId: signingKey.keyId,
        createdAt,
      };

      if (groupId) {
        await relayToGroup(groupId, relayed, users);
      } else {
        await touchDirectThread(userId, recipientId!, messageId, createdAt);
        await relayToUser(recipientId!, relayed, users, threadId);
        // The sender already rendered this message optimistically. Echoing it
        // to their other devices is useful, but it must never be queued for
        // offline delivery to the sender: that would replay every sent message
        // back to its author on the next connection.
        await relayToUser(userId, relayed, users, threadId, socket, {
          queueIfOffline: false,
        });
      }
      socket.emit('message_sent', { messageId, threadId, createdAt, signature });
    });

    socket.on('group_key_distribution', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }

      const body = (payload ?? {}) as Record<string, unknown>;
      const groupId = asString(body.groupId);
      const gmkVersion = Number(body.gmkVersion);
      const groupMasterKeyId = asString(body.groupMasterKeyId);
      const createdAt = asString(body.createdAt);
      const signature = asString(body.signature);
      const rawEntries = body.encryptedGMKByMember;

      if (
        !groupId ||
        !Number.isInteger(gmkVersion) ||
        !groupMasterKeyId ||
        !createdAt ||
        !validIsoTimestamp(createdAt) ||
        !signature ||
        !Array.isArray(rawEntries) ||
        rawEntries.length > 1000
      ) {
        return emitError(
          socket,
          'invalid_request',
          'groupId, gmkVersion, signature and wrapped keys are required',
        );
      }

      const entries: Array<Record<string, unknown>> = [];
      for (const raw of rawEntries) {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
          return emitError(socket, 'invalid_request', 'each wrapped key must be an object');
        }
        const entry = raw as Record<string, unknown>;
        if (
          typeof entry.memberKeyId !== 'string' ||
          typeof entry.wrappedGMK !== 'string' ||
          typeof entry.iv !== 'string' ||
          typeof entry.ephemeralPublicKey !== 'string' ||
          Number(entry.gmkVersion) !== gmkVersion
        ) {
          return emitError(socket, 'invalid_request', 'a wrapped key is incomplete');
        }
        entries.push(entry);
      }

      const membership = await selectOne('group_member', {
        group_id: groupId,
        user_id: userId,
        status: 'active',
      });
      if (!membership || !Number(membership.is_admin)) {
        return emitError(socket, 'forbidden', 'only group admins can distribute group keys');
      }

      const group = await selectOne('group', { id: groupId }, ['id', 'gm_version']);
      if (!group) return emitError(socket, 'not_found', 'group not found');
      const currentVersion = Number(group.gm_version) || 1;
      if (gmkVersion < currentVersion || gmkVersion > currentVersion + 1) {
        return emitError(
          socket,
          'invalid_version',
          `group key version must be ${currentVersion} or ${currentVersion + 1}`,
        );
      }

      const active = await activeGroupMemberKeys(groupId);
      for (const entry of entries) {
        if (!active.keyToUser.has(String(entry.memberKeyId))) {
          return emitError(
            socket,
            'unknown_member_key',
            'a wrapped key does not match an active member key',
          );
        }
      }

      // A new generation must cover every active member that has a published
      // X25519 key. Re-sends at the current version may target one requester.
      if (gmkVersion > currentVersion) {
        const provided = new Set(entries.map((entry) => String(entry.memberKeyId)));
        const missing = [...active.userToKey.values()].filter((keyId) => !provided.has(keyId));
        if (missing.length > 0) {
          return emitError(
            socket,
            'incomplete_key_distribution',
            `group key distribution is missing ${missing.length} active member(s)`,
          );
        }
      }

      const signingKey = await activeSigningKey(userId);
      if (!signingKey) {
        return emitError(
          socket,
          'signing_key_required',
          'publish an Ed25519 signing key before distributing group keys',
        );
      }
      const signedPayload = groupKeySigningPayload({
        groupId,
        gmkVersion,
        groupMasterKeyId,
        createdAt,
        encryptedGMKByMember: entries,
      });
      if (!verifyEd25519Signature(signedPayload, signature, signingKey.publicKeyHex)) {
        return emitError(
          socket,
          'invalid_signature',
          'group key distribution signature is invalid',
        );
      }

      const event = {
        event: 'group_key_distribution',
        groupId,
        gmkVersion,
        groupMasterKeyId,
        encryptedGMKByMember: entries,
        distributedBy: userId,
        signature,
        signatureKeyId: signingKey.keyId,
        createdAt,
      };

      const members = await selectAll(
        'group_member',
        { group_id: groupId, status: 'active' },
        1000,
        ['user_id'],
      );
      for (const member of members) {
        await relayToUser(String(member.user_id), event, users, `group:${groupId}`);
      }

      await updateRows(
        'group',
        { id: groupId },
        { gm_version: gmkVersion, gm_locked: true, updated_at: now() },
      );
    });

    socket.on('request_group_key', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }
      const body = (payload ?? {}) as Record<string, unknown>;
      const groupId = asString(body.groupId);
      if (!groupId) return emitError(socket, 'invalid_request', 'groupId is required');

      const membership = await selectOne('group_member', {
        group_id: groupId,
        user_id: userId,
        status: 'active',
      });
      if (!membership) return emitError(socket, 'forbidden', 'not a member of this group');

      const group = await selectOne('group', { id: groupId }, ['id', 'gm_version']);
      if (!group) return emitError(socket, 'not_found', 'group not found');

      const event = {
        event: 'group_key_request',
        groupId,
        requesterId: userId,
        gmkVersion: Number(group.gm_version ?? 1),
      };
      const admins = await selectAll('group_member', { group_id: groupId, is_admin: true }, 100, [
        'user_id',
      ]);
      for (const admin of admins) {
        const adminId = String(admin.user_id);
        if (adminId === userId) continue;
        await relayToUser(adminId, event, users, `group:${groupId}`);
      }
      socket.emit('group_key_requested', { ok: true, groupId });
    });

    socket.on('publish_public_key', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }
      const body = (payload ?? {}) as Record<string, unknown>;
      const keyId = asString(body.keyId);
      const x25519 = asString(body.x25519) ?? asString(body.publicKey);
      const ed25519 = asString(body.ed25519) ?? asString(body.signingPublicKey);
      if (!keyId || keyId.length > 64) {
        return emitError(socket, 'invalid_request', 'keyId is required');
      }
      if (!x25519 || !/^[0-9a-f]{64}$/i.test(x25519)) {
        return emitError(socket, 'invalid_request', 'x25519 public key must be 32 bytes of hex');
      }
      if (!ed25519 || !/^[0-9a-f]{64}$/i.test(ed25519)) {
        return emitError(socket, 'invalid_request', 'ed25519 signing key must be 32 bytes of hex');
      }

      const createdAt = now();
      const existing = await selectOne('crypto_key', { owner_id: userId, key_id: keyId }, ['id']);
      if (existing) {
        await updateRows(
          'crypto_key',
          { owner_id: userId, key_id: keyId },
          {
            x25519_public: x25519,
            ed25519_public: ed25519,
            status: 'active',
            updated_at: createdAt,
          },
        );
      } else {
        await insertRow('crypto_key', {
          id: randomUUID(),
          owner_id: userId,
          key_type: 'identity',
          key_id: keyId,
          public_key_pem: null,
          private_key_pem: null,
          x25519_public: x25519,
          ed25519_public: ed25519,
          usage: 'identity',
          status: 'active',
          created_at: createdAt,
          updated_at: createdAt,
        });
      }
      socket.emit('public_key_published', { ok: true, keyId, ed25519 });
    });

    socket.on('user_typing', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }
      const body = (payload ?? {}) as Record<string, unknown>;
      const threadId = asString(body.threadId);
      const groupId = asString(body.groupId);
      const isTyping = Boolean(body.isTyping);

      if (!threadId && !groupId)
        return emitError(socket, 'invalid_request', 'threadId or groupId is required');

      const room = threadId ?? groupId;
      const channelType = groupId ? 'group' : 'direct';

      if (groupId) {
        const membership = await selectOne('group_member', { group_id: groupId, user_id: userId });
        if (!membership) return emitError(socket, 'forbidden', 'not a member of this group');
      } else if (threadId) {
        const parsed = parseDirectThreadId(threadId);
        if (!parsed || !parsed.includes(userId)) {
          return emitError(socket, 'forbidden', 'not a participant of this conversation');
        }
      }

      io.to(`${channelType}:${room}`).emit('user_typing', { threadId, groupId, userId, isTyping });
    });

    socket.on('message_read', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }
      const body = (payload ?? {}) as Record<string, unknown>;
      const threadId = asString(body.threadId);
      const groupId = asString(body.groupId);
      const messageIds = Array.isArray(body.messageIds) ? body.messageIds.slice(0, 1000) : [];
      const readAt = asString(body.readAt);

      if (!threadId && !groupId)
        return emitError(socket, 'invalid_request', 'threadId or groupId is required');
      if (!messageIds.length && !readAt) return;

      const room = threadId ?? groupId;
      const channelType = groupId ? 'group' : 'direct';

      if (groupId) {
        const membership = await selectOne('group_member', { group_id: groupId, user_id: userId });
        if (!membership) return emitError(socket, 'forbidden', 'not a member of this group');
        if (readAt) {
          await updateRows(
            'group_member',
            { group_id: groupId, user_id: userId },
            { last_read_at: readAt },
          );
        }
      } else if (threadId) {
        const parsed = parseDirectThreadId(threadId);
        if (!parsed || !parsed.includes(userId)) {
          return emitError(socket, 'forbidden', 'not a participant of this conversation');
        }
        if (readAt) {
          await updateRows(
            'direct_message_thread',
            { id: threadId },
            { last_read_at: readAt, updated_at: readAt },
          );
        }
      }

      io.to(`${channelType}:${room}`).emit('message_read', {
        threadId,
        groupId,
        userId,
        messageIds,
        readAt,
      });
    });

    // Plaintext edits are intentionally unsupported. A future edit feature must
    // carry a signed ciphertext envelope, not an `editedText` string.

    socket.on('delete_message', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }
      const body = (payload ?? {}) as Record<string, unknown>;
      const messageId = asString(body.messageId);
      const threadId = asString(body.threadId);
      const groupId = asString(body.groupId);

      if (!messageId || (!threadId && !groupId)) {
        return emitError(
          socket,
          'invalid_request',
          'messageId and threadId or groupId is required',
        );
      }

      const room = threadId ?? groupId;
      const channelType = groupId ? 'group' : 'direct';

      const where: Record<string, unknown> = { id: messageId };
      if (threadId) where.thread_id = threadId;
      if (groupId) where.thread_id = groupId;

      const message = await selectOne('message', where);
      if (!message) return emitError(socket, 'not_found', 'message not found');

      if (String(message.sender_id) !== userId) {
        if (!groupId) {
          return emitError(socket, 'forbidden', 'you may only delete your own messages');
        }
        const membership = await selectOne('group_member', { group_id: groupId, user_id: userId });
        if (!membership || !Number(membership.is_admin)) {
          return emitError(socket, 'forbidden', 'only group admins may delete this message');
        }
      }

      await deleteMediaObjectsForMessage(messageId);
      await deleteRows('message', { id: messageId });
      io.to(`${channelType}:${room}`).emit('delete_message', {
        messageId,
        threadId,
        groupId,
        deletedBy: userId,
      });
    });

    // After a member leaves, the server asks exactly one remaining admin to
    // rotate the group key. The request carries no secrets and is rate-limited;
    // the admin client performs the actual client-side rotation.
    socket.on('group_key_rotation_needed', async (payload: unknown) => {
      if (!consumeSocketToken(socket)) {
        return emitError(socket, 'rate_limited', 'too many events; slow down');
      }
      if (payloadTooLarge(payload)) {
        return emitError(socket, 'payload_too_large', 'socket payload is too large');
      }
      const body = (payload ?? {}) as Record<string, unknown>;
      const groupId = asString(body.groupId);
      if (!groupId) return emitError(socket, 'invalid_request', 'groupId is required');

      const group = await selectOne('group', { id: groupId }, ['id']);
      if (!group) return emitError(socket, 'not_found', 'group not found');

      const admins = await selectAll(
        'group_member',
        { group_id: groupId, is_admin: true, status: 'active' },
        100,
        ['user_id', 'joined_at'],
        { column: 'joined_at', direction: 'asc' },
      );
      const admin = admins[0];
      if (!admin) return;

      await relayToUser(
        String(admin.user_id),
        { event: 'group_key_rotation_needed', groupId, requestedBy: userId },
        users,
        `group:${groupId}`,
      );
    });
  });
}

async function flushUserOfflineQueue(
  userId: string,
  users: Map<string, Set<Socket>>,
): Promise<void> {
  const queued = await selectAll(
    'offline_queue_item',
    { user_id: userId, status: 'queued' },
    1000,
    ['id', 'payload', 'channel_id'],
  );
  for (const item of queued) {
    const payload = typeof item.payload === 'string' ? JSON.parse(item.payload) : item.payload;
    const channelId =
      typeof item.channel_id === 'string' && item.channel_id.length > 0
        ? item.channel_id
        : `direct:${userId}`;
    await relayToUser(userId, payload, users, channelId);
    await updateRows(
      'offline_queue_item',
      { id: item.id },
      { status: 'delivered', delivered_at: now() },
    );
    await deleteRows('offline_queue_item', { id: item.id });
  }
}

async function relayToUser(
  userId: string,
  payload: unknown,
  users: Map<string, Set<Socket>>,
  channelId: string,
  except?: Socket,
  options: { queueIfOffline?: boolean } = {},
): Promise<void> {
  const sockets = users.get(userId);
  const serialized = JSON.stringify(payload);
  let delivered = false;

  if (sockets?.size) {
    for (const s of sockets) {
      if (except && s === except) continue;
      s.emit('receive_message', serialized);
      delivered = true;
    }
  }

  if (!delivered && options.queueIfOffline !== false) {
    void insertRow('offline_queue_item', {
      id: randomUUID(),
      user_id: userId,
      channel_type: channelId.startsWith('group:') ? 'group' : 'direct',
      channel_id: channelId,
      message_id: '',
      payload: serialized,
      enqueued_at: now(),
      delivered_at: null,
      status: 'queued',
    }).catch(() => {});
  }
}

async function relayToGroup(
  groupId: string,
  payload: unknown,
  users: Map<string, Set<Socket>>,
): Promise<void> {
  const members = await selectAll('group_member', { group_id: groupId, status: 'active' }, 1000, [
    'user_id',
  ]);
  for (const member of members) {
    await relayToUser(String(member.user_id), payload, users, `group:${groupId}`);
  }
}

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Server } from 'socket.io';
import { io as ioClient, type Socket as ClientSocket } from 'socket.io-client';
import { createSchema, insertRow, resetDb, selectAll, selectOne, updateRows } from '../db/index.js';
import { signAccessToken } from '../services/auth.service.js';
import {
  generateSigningKeyPair,
  messageSigningPayload,
  signPayload,
} from '../services/crypto.service.js';
import { resetCache } from '../services/cache.js';
import { createSocketServer } from './server.js';
import type { SocketContext } from './types.js';

interface Relay {
  io: Server;
  ctx: SocketContext;
  port: number;
  close(): Promise<void>;
}

let relay: Relay | null = null;
const clients: ClientSocket[] = [];

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

async function startRelay(): Promise<Relay> {
  const httpServer = http.createServer();
  const io = new Server(httpServer, { cors: { origin: true }, path: '/socket.io' });
  const ctx: SocketContext = { io, users: new Map(), httpServer };
  createSocketServer(ctx);

  await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  const { port } = httpServer.address() as AddressInfo;

  return {
    io,
    ctx,
    port,
    close: () =>
      new Promise<void>((resolve) => {
        for (const client of clients.splice(0)) client.disconnect();
        io.close(() => resolve());
      }),
  };
}

async function createUser(
  username: string,
): Promise<{ id: string; username: string; token: string }> {
  const id = randomUUID();
  const timestamp = nowIso();
  await insertRow('user', {
    id,
    username,
    email: `${username}@socket.test`,
    password_hash: 'not-used-by-the-relay',
    avatar_url: null,
    bio: null,
    token_version: 0,
    is_online: false,
    email_verified: true,
    totp_secret: null,
    totp_enabled: false,
    created_at: timestamp,
    updated_at: timestamp,
  });
  return { id, username, token: signAccessToken(id, username, 0) };
}

interface Signer {
  keyId: string;
  privateKeyHex: string;
}

/** Publish an Ed25519 identity signing key for a user, as the client would. */
async function enableSigning(user: { id: string; username: string }): Promise<Signer> {
  const { publicKeyHex, privateKeyHex } = generateSigningKeyPair();
  const timestamp = nowIso();
  const keyId = `key-${user.username}-signing`;
  await insertRow('crypto_key', {
    id: randomUUID(),
    owner_id: user.id,
    key_type: 'identity',
    key_id: keyId,
    public_key_pem: null,
    private_key_pem: null,
    x25519_public: null,
    ed25519_public: publicKeyHex,
    usage: 'identity',
    status: 'active',
    created_at: timestamp,
    updated_at: timestamp,
  });
  return { keyId, privateKeyHex };
}

function directThreadIdFor(a: string, b: string): string {
  return `thread_direct_${[a, b].sort().join('__')}`;
}

/** Build a correctly signed `send_message` payload for a direct or group target. */
function signedMessage(
  sender: { id: string },
  signer: Signer,
  target: { recipientId?: string; groupId?: string },
  body: {
    messageId: string;
    cipherBundle: Record<string, unknown>;
    type?: string;
    metadata?: Record<string, unknown> | null;
  },
): Record<string, unknown> {
  const type = body.type ?? 'text';
  const createdAt = nowIso();
  const metadata = body.metadata ?? null;
  const threadId = target.groupId ?? directThreadIdFor(sender.id, target.recipientId!);
  const signature = signPayload(
    messageSigningPayload({
      messageId: body.messageId,
      threadId,
      senderId: sender.id,
      type,
      createdAt,
      cipherBundle: body.cipherBundle,
      metadata,
    }),
    signer.privateKeyHex,
  );
  return {
    ...target,
    messageId: body.messageId,
    type,
    createdAt,
    metadata,
    signature,
    cipherBundle: body.cipherBundle,
  };
}

async function createGroupWithMembers(
  name: string,
  adminId: string,
  memberIds: string[],
): Promise<string> {
  const groupId = `group-${randomUUID()}`;
  const timestamp = nowIso();
  await insertRow('group', {
    id: groupId,
    name,
    admin_id: adminId,
    is_private: false,
    gm_locked: false,
    gm_version: 1,
    created_at: timestamp,
    updated_at: timestamp,
  });
  for (const userId of [adminId, ...memberIds]) {
    await insertRow('group_member', {
      id: randomUUID(),
      group_id: groupId,
      user_id: userId,
      joined_at: timestamp,
      is_admin: userId === adminId,
      joined_via_invite: false,
      invite_token: null,
      last_read_message_id: null,
      last_read_at: null,
      status: 'active',
    });
  }
  return groupId;
}

/** Build a client that does not connect until `socket.connect()` is called. */
function openSocket(port: number, token?: string): ClientSocket {
  const socket = ioClient(`http://127.0.0.1:${port}`, {
    transports: ['websocket'],
    reconnection: false,
    forceNew: true,
    autoConnect: false,
    auth: token ? { token } : {},
  });
  clients.push(socket);
  return socket;
}

function waitFor(socket: ClientSocket, event: string, timeoutMs = 3000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.off(event, onEvent);
      reject(new Error(`timed out waiting for "${event}"`));
    }, timeoutMs);
    const onEvent = (payload: unknown) => {
      clearTimeout(timer);
      resolve(payload);
    };
    socket.once(event, onEvent);
  });
}

function expectNoEvent(socket: ClientSocket, event: string, windowMs = 200): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.off(event, onEvent);
      resolve();
    }, windowMs);
    const onEvent = (payload: unknown) => {
      clearTimeout(timer);
      reject(new Error(`unexpected "${event}": ${JSON.stringify(payload)}`));
    };
    socket.once(event, onEvent);
  });
}

async function connect(socket: ClientSocket): Promise<ClientSocket> {
  const connected = waitFor(socket, 'connect');
  socket.connect();
  await connected;
  return socket;
}

async function connectFailure(socket: ClientSocket): Promise<string> {
  const failed = waitFor(socket, 'connect_error');
  socket.connect();
  const error = (await failed) as Error;
  return error.message;
}

beforeEach(async () => {
  resetDb();
  await createSchema();
  resetCache();
  relay = await startRelay();
});

afterEach(async () => {
  await relay?.close();
  relay = null;
});

describe('E2EE socket relay', () => {
  it('rejects connections without a token, with a bad token, or with a revoked token', async () => {
    const live = relay!;
    expect(await connectFailure(openSocket(live.port))).toBe('missing token');
    expect(await connectFailure(openSocket(live.port, 'not-a-jwt'))).toBe(
      'invalid or expired token',
    );

    const alice = await createUser('alice');
    await updateRows('user', { id: alice.id }, { token_version: 1 });
    expect(await connectFailure(openSocket(live.port, alice.token))).toBe(
      'invalid or expired token',
    );
    expect(live.ctx.users.size).toBe(0);
  });

  it('relays a ciphertext envelope to the recipient and persists only the envelope', async () => {
    const live = relay!;
    const alice = await createUser('alice');
    const bob = await createUser('bob');
    const signer = await enableSigning(alice);
    const aliceSocket = await connect(openSocket(live.port, alice.token));
    const bobSocket = await connect(openSocket(live.port, bob.token));

    const delivered = waitFor(bobSocket, 'receive_message');
    const sent = waitFor(aliceSocket, 'message_sent');
    aliceSocket.emit(
      'send_message',
      signedMessage(
        alice,
        signer,
        { recipientId: bob.id },
        {
          messageId: 'msg-00001',
          cipherBundle: {
            ciphertext: 'base64-ciphertext',
            iv: 'base64-iv',
            alg: 'aes-256-gcm',
            keyId: 'key-alice-1',
          },
        },
      ),
    );

    const received = JSON.parse((await delivered) as string) as Record<string, unknown>;
    const ack = (await sent) as Record<string, unknown>;
    expect(received.senderId).toBe(alice.id);
    expect(received.messageId).toBe(ack.messageId);
    expect(received.threadId).toBe(ack.threadId);
    expect(received.cipherBundle).toEqual({
      ciphertext: 'base64-ciphertext',
      iv: 'base64-iv',
      alg: 'aes-256-gcm',
      keyId: 'key-alice-1',
    });

    const rows = await selectAll('message', { thread_id: String(ack.threadId) });
    expect(rows).toHaveLength(1);
    expect(rows[0].content).toBeNull();
    // The sender's own echo must not be queued as an undelivered message.
    expect(await selectAll('offline_queue_item', { user_id: alice.id })).toHaveLength(0);
    expect(rows[0].sender_id).toBe(alice.id);
    expect(rows[0].encryption_alg).toBe('aes-256-gcm');
    expect(JSON.parse(String(rows[0].encrypted_content))).toMatchObject({
      ciphertext: 'base64-ciphertext',
    });

    const thread = await selectOne('direct_message_thread', { id: String(ack.threadId) });
    expect(thread?.last_message_id).toBe(ack.messageId);
    const senderIsA = String(thread?.user_a_id) === alice.id;
    expect(thread?.[senderIsA ? 'unread_count_a' : 'unread_count_b']).toBe(0);
    expect(thread?.[senderIsA ? 'unread_count_b' : 'unread_count_a']).toBe(1);
  });

  it('refuses plaintext messages and persists nothing', async () => {
    const live = relay!;
    const alice = await createUser('alice');
    const bob = await createUser('bob');
    const aliceSocket = await connect(openSocket(live.port, alice.token));
    await connect(openSocket(live.port, bob.token));

    const rejection = waitFor(aliceSocket, 'receive_message');
    aliceSocket.emit('send_message', {
      recipientId: bob.id,
      type: 'text',
      content: 'hello in the clear',
    });

    const payload = (await rejection) as { code?: string; error?: string };
    expect(payload.code).toBe('encryption_required');
    expect(payload.error).toMatch(/cipherBundle/);
    expect(await selectAll('message', {})).toHaveLength(0);
  });

  it('fans group messages out to members only and blocks non-member sends', async () => {
    const live = relay!;
    const alice = await createUser('alice');
    const bob = await createUser('bob');
    const carol = await createUser('carol');
    const groupId = await createGroupWithMembers('relay team', alice.id, [bob.id]);

    const signer = await enableSigning(alice);
    const aliceSocket = await connect(openSocket(live.port, alice.token));
    const bobSocket = await connect(openSocket(live.port, bob.token));
    const carolSocket = await connect(openSocket(live.port, carol.token));

    const bobGets = waitFor(bobSocket, 'receive_message');
    const carolSilent = expectNoEvent(carolSocket, 'receive_message');
    const sent = waitFor(aliceSocket, 'message_sent');
    aliceSocket.emit(
      'send_message',
      signedMessage(
        alice,
        signer,
        { groupId },
        {
          messageId: 'gmsg-00001',
          cipherBundle: {
            ciphertext: 'group-cipher',
            iv: 'base64-iv',
            alg: 'aes-256-gcm',
            keyId: 'key-alice-1',
            gmkId: 'gmk-1',
          },
        },
      ),
    );

    const received = JSON.parse((await bobGets) as string) as Record<string, unknown>;
    expect(received.threadId).toBe(groupId);
    expect(received.cipherBundle).toMatchObject({ ciphertext: 'group-cipher', gmkId: 'gmk-1' });
    await carolSilent;
    await sent;

    const rows = await selectAll('message', { thread_id: groupId });
    expect(rows).toHaveLength(1);
    expect(rows[0].gmk_id).toBe('gmk-1');

    // Membership is checked before the signature so outsiders cannot probe or
    // write into a group they were never added to.
    const denial = waitFor(carolSocket, 'receive_message');
    carolSocket.emit('send_message', {
      groupId,
      messageId: 'carol-00001',
      createdAt: nowIso(),
      cipherBundle: { ciphertext: 'not-a-member' },
    });
    expect(((await denial) as { code?: string }).code).toBe('forbidden');
    expect(await selectAll('message', { thread_id: groupId })).toHaveLength(1);
  });

  it('enforces room membership when joining a group channel', async () => {
    const live = relay!;
    const alice = await createUser('alice');
    const carol = await createUser('carol');
    const groupId = await createGroupWithMembers('private room', alice.id, []);
    const aliceSocket = await connect(openSocket(live.port, alice.token));
    const carolSocket = await connect(openSocket(live.port, carol.token));

    const joined = waitFor(aliceSocket, 'room_joined');
    aliceSocket.emit('join_room', { groupId });
    expect((await joined) as { ok?: boolean }).toMatchObject({ ok: true });

    const denied = waitFor(carolSocket, 'receive_message');
    carolSocket.emit('join_room', { groupId });
    expect(((await denied) as { code?: string }).code).toBe('forbidden');
  });

  it('queues messages for offline users and flushes them on connect', async () => {
    const live = relay!;
    const alice = await createUser('alice');
    const bob = await createUser('bob');
    const signer = await enableSigning(alice);
    const aliceSocket = await connect(openSocket(live.port, alice.token));

    const sent = waitFor(aliceSocket, 'message_sent');
    aliceSocket.emit(
      'send_message',
      signedMessage(
        alice,
        signer,
        { recipientId: bob.id },
        {
          messageId: 'test-msg-1',
          cipherBundle: {
            ciphertext: 'while-you-were-away',
            iv: 'base64-iv',
            alg: 'aes-256-gcm',
            keyId: 'key-alice-1',
          },
        },
      ),
    );
    const ack = (await sent) as { messageId: string };

    const queued = await selectAll('offline_queue_item', { user_id: bob.id, status: 'queued' });
    expect(queued).toHaveLength(1);
    expect(queued[0].channel_type).toBe('direct');
    expect(JSON.parse(String(queued[0].payload))).toMatchObject({ messageId: ack.messageId });

    // Attach the listener before connecting: the relay flushes the backlog as
    // part of the connection handler. A signed message is required before the
    // relay will persist anything.
    const bobSocket = openSocket(live.port, bob.token);
    const flushed = waitFor(bobSocket, 'receive_message');
    const connected = waitFor(bobSocket, 'connect');
    bobSocket.connect();

    const payload = JSON.parse((await flushed) as string) as Record<string, unknown>;
    expect(payload.messageId).toBe(ack.messageId);
    expect(payload.cipherBundle).toMatchObject({ ciphertext: 'while-you-were-away' });
    await connected;

    expect(await selectAll('offline_queue_item', { user_id: bob.id })).toHaveLength(0);
  });

  it('broadcasts presence and marks the user offline on disconnect', async () => {
    const live = relay!;
    const alice = await createUser('alice');
    const bob = await createUser('bob');
    const aliceSocket = await connect(openSocket(live.port, alice.token));

    const bobOnline = waitFor(aliceSocket, 'user_status');
    const bobSocket = await connect(openSocket(live.port, bob.token));
    expect(await bobOnline).toMatchObject({ userId: bob.id, isOnline: true });
    expect((await selectOne('user', { id: bob.id }))?.is_online).toBeTruthy();

    const bobOffline = waitFor(aliceSocket, 'user_status');
    bobSocket.disconnect();
    expect(await bobOffline).toMatchObject({ userId: bob.id, isOnline: false });
    expect((await selectOne('user', { id: bob.id }))?.is_online).toBeFalsy();
  });

  it('asks group admins for a redistributed group key and rejects outsiders', async () => {
    const live = relay!;
    const adminUser = await createUser('admin');
    const member = await createUser('member');
    const outsider = await createUser('outsider');
    const groupId = await createGroupWithMembers('key rotation', adminUser.id, [member.id]);

    const adminSocket = await connect(openSocket(live.port, adminUser.token));
    const memberSocket = await connect(openSocket(live.port, member.token));
    const outsiderSocket = await connect(openSocket(live.port, outsider.token));

    const requested = waitFor(adminSocket, 'receive_message');
    const acknowledged = waitFor(memberSocket, 'group_key_requested');
    memberSocket.emit('request_group_key', { groupId });

    const payload = JSON.parse((await requested) as string) as Record<string, unknown>;
    expect(payload).toMatchObject({
      event: 'group_key_request',
      groupId,
      requesterId: member.id,
      gmkVersion: 1,
    });
    expect(await acknowledged).toMatchObject({ ok: true, groupId });

    const denial = waitFor(outsiderSocket, 'receive_message');
    outsiderSocket.emit('request_group_key', { groupId });
    expect(((await denial) as { code?: string }).code).toBe('forbidden');
  });

  it('validates published identity keys before storing them', async () => {
    const live = relay!;
    const alice = await createUser('alice');
    const aliceSocket = await connect(openSocket(live.port, alice.token));

    const invalid = waitFor(aliceSocket, 'receive_message');
    aliceSocket.emit('publish_public_key', { keyId: 'k1', x25519: 'too-short' });
    expect(((await invalid) as { code?: string }).code).toBe('invalid_request');

    // A signature-less identity key is useless for message authentication, so
    // the relay refuses an X25519 key without a matching Ed25519 key.
    const noSigning = waitFor(aliceSocket, 'receive_message');
    aliceSocket.emit('publish_public_key', { keyId: 'k2', x25519: 'ab'.repeat(32) });
    expect(((await noSigning) as { code?: string }).code).toBe('invalid_request');

    const signing = generateSigningKeyPair();
    const accepted = waitFor(aliceSocket, 'public_key_published');
    aliceSocket.emit('publish_public_key', {
      keyId: 'k1',
      x25519: 'ab'.repeat(32),
      ed25519: signing.publicKeyHex,
    });
    expect(await accepted).toMatchObject({ ok: true, keyId: 'k1' });

    const keys = await selectAll('crypto_key', { owner_id: alice.id });
    expect(keys).toHaveLength(1);
    expect(keys[0].x25519_public).toBe('ab'.repeat(32));
    expect(keys[0].ed25519_public).toBe(signing.publicKeyHex);
  });

  it('rejects unsigned messages, bad signatures and replayed message ids', async () => {
    const live = relay!;
    const alice = await createUser('alice');
    const bob = await createUser('bob');
    const aliceSocket = await connect(openSocket(live.port, alice.token));
    await connect(openSocket(live.port, bob.token));

    const unsigned = waitFor(aliceSocket, 'receive_message');
    aliceSocket.emit('send_message', {
      recipientId: bob.id,
      messageId: 'unsigned-001',
      createdAt: nowIso(),
      cipherBundle: { ciphertext: 'opaque', iv: 'iv', alg: 'aes-256-gcm' },
    });
    expect(((await unsigned) as { code?: string }).code).toBe('signature_required');

    const noKey = waitFor(aliceSocket, 'receive_message');
    aliceSocket.emit('send_message', {
      recipientId: bob.id,
      messageId: 'nokey-00001',
      createdAt: nowIso(),
      signature: 'A'.repeat(43) + '=',
      cipherBundle: { ciphertext: 'opaque', iv: 'iv', alg: 'aes-256-gcm' },
    });
    expect(((await noKey) as { code?: string }).code).toBe('signing_key_required');

    const signer = await enableSigning(alice);
    const forged = signedMessage(
      alice,
      signer,
      { recipientId: bob.id },
      {
        messageId: 'forged-0001',
        cipherBundle: { ciphertext: 'opaque', iv: 'iv', alg: 'aes-256-gcm' },
      },
    );
    forged.signature = signPayload('some-other-payload', signer.privateKeyHex);
    const badSignature = waitFor(aliceSocket, 'receive_message');
    aliceSocket.emit('send_message', forged);
    expect(((await badSignature) as { code?: string }).code).toBe('invalid_signature');

    const accepted = waitFor(aliceSocket, 'message_sent');
    aliceSocket.emit(
      'send_message',
      signedMessage(
        alice,
        signer,
        { recipientId: bob.id },
        {
          messageId: 'signed-00001',
          cipherBundle: { ciphertext: 'opaque', iv: 'iv', alg: 'aes-256-gcm' },
        },
      ),
    );
    await accepted;

    const duplicate = waitFor(aliceSocket, 'receive_message');
    aliceSocket.emit(
      'send_message',
      signedMessage(
        alice,
        signer,
        { recipientId: bob.id },
        {
          messageId: 'signed-00001',
          cipherBundle: { ciphertext: 'opaque', iv: 'iv', alg: 'aes-256-gcm' },
        },
      ),
    );
    expect(((await duplicate) as { code?: string }).code).toBe('duplicate_message');

    expect(await selectAll('message', { sender_id: alice.id })).toHaveLength(1);
  });
});

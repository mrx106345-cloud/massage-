import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import app from './app.ts';
import { createSchema, insertRow, resetDb, selectOne } from './db/index.ts';
import { resetCache } from './services/cache.ts';
import { decryptFileBytes, encryptFileBytes } from '../public/js/crypto.js';

const PASSWORD = 'supersecret1';
const MEDIA_ROOT = path.resolve(process.cwd(), 'data', 'media');
const mediaFilesToRemove = [];

async function signup(username) {
  const res = await request(app)
    .post('/api/v1/auth/signup')
    .send({ email: `${username}@example.com`, username, password: PASSWORD });
  expect(res.status).toBe(201);
  return res.body;
}

function auth(account) {
  return { authorization: `Bearer ${account.token}` };
}

function binaryParser(res, callback) {
  const chunks = [];
  res.on('data', (chunk) => chunks.push(chunk));
  res.on('end', () => callback(null, Buffer.concat(chunks)));
  res.on('error', (err) => callback(err, Buffer.alloc(0)));
}

async function presign(account) {
  const res = await request(app)
    .post('/api/v1/media/presign')
    .set(auth(account))
    .send({ fileType: 'image/png', fileName: 'photo.png', sizeBytes: 6 });
  expect(res.status).toBe(200);
  const row = await selectOne('media_file', { id: res.body.mediaId });
  if (row) mediaFilesToRemove.push(path.resolve(MEDIA_ROOT, String(row.storage_key)));
  return res.body;
}

beforeEach(async () => {
  resetDb();
  await createSchema();
  resetCache();
});

afterEach(() => {
  for (const file of mediaFilesToRemove.splice(0)) {
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
});

describe('encrypted attachment pipeline', () => {
  it('uploads ciphertext that only the conversation recipient can fetch and decrypt', async () => {
    const alice = await signup('alice');
    const bob = await signup('bob');
    const carol = await signup('carol');
    const presigned = await presign(alice);

    const bytes = new Uint8Array([0x00, 0x01, 0x02, 0xfe, 0xff, 0x10]);
    const sealed = await encryptFileBytes(bytes, presigned.mediaId);

    const upload = await request(app)
      .put(presigned.uploadUrl)
      .set('content-type', 'application/octet-stream')
      .send(Buffer.from(sealed.ciphertext));
    expect(upload.status).toBe(200);

    // The server-visible metadata carries only the opaque media id. The AES key
    // and IV live inside the E2EE message envelope (simulated by this row).
    const threadId = `thread_direct_${[alice.user.id, bob.user.id].sort().join('__')}`;
    const createdAt = new Date().toISOString();
    await insertRow('message', {
      id: randomUUID(),
      thread_id: threadId,
      sender_id: alice.user.id,
      parent_id: null,
      content_type: 'image',
      content: null,
      encrypted_content: JSON.stringify({
        ciphertext: 'opaque',
        alg: 'aes-256-gcm',
        keyId: 'key-1',
      }),
      encryption_alg: 'aes-256-gcm',
      encryption_key_id: 'key-1',
      gmk_id: null,
      metadata: JSON.stringify({ mediaId: presigned.mediaId }),
      status: 'sent',
      delivery_receipts: null,
      created_at: createdAt,
      updated_at: createdAt,
    });

    const stranger = await request(app).get(`/api/v1/media/${presigned.mediaId}`).set(auth(carol));
    expect(stranger.status).toBe(403);

    const recipient = await request(app).get(`/api/v1/media/${presigned.mediaId}`).set(auth(bob));
    expect(recipient.status).toBe(200);

    const download = await request(app)
      .get(recipient.body.downloadUrl)
      .buffer(true)
      .parse(binaryParser);
    expect(download.status).toBe(200);

    const opened = await decryptFileBytes(
      new Uint8Array(download.body),
      sealed.key,
      sealed.iv,
      presigned.mediaId,
    );
    expect(Buffer.from(opened).equals(Buffer.from(bytes))).toBe(true);

    // Ciphertext is bound to its media id, so it cannot be replayed as another
    // attachment even by someone who has both the bytes and the key.
    await expect(
      decryptFileBytes(new Uint8Array(download.body), sealed.key, sealed.iv, 'another-media-id'),
    ).rejects.toThrow();
  });
});

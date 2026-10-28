import { beforeAll, describe, expect, it } from 'vitest';
import nacl from 'tweetnacl';
import {
  decryptFileBytes,
  decryptForGroup,
  decryptForRecipient,
  encryptFileBytes,
  encryptForGroup,
  encryptForRecipient,
  fromBase64,
  generateGroupMasterKey,
  generateIdentity,
  identityFromSecret,
  setNacl,
  toBase64,
  unwrapGroupKey,
  wrapGroupKey,
} from '../public/js/crypto.js';
import {
  decryptWithRecipient,
  distributeGroupMasterKey,
  encryptForRecipient as serverEncrypt,
  generateKeyPackage,
  groupKeySigningPayload as serverGroupKeySigningPayload,
  messageSigningPayload as serverMessageSigningPayload,
  unwrapGroupMasterKey,
  verifyEd25519Signature,
} from './services/crypto.service.ts';
import {
  groupKeySigningPayload as browserGroupKeySigningPayload,
  messageSigningPayload,
  signGroupKeyDistribution,
  signMessage,
} from '../public/js/crypto.js';

beforeAll(() => setNacl(nacl));

describe('browser E2EE primitives', () => {
  it('round-trips a direct message between two client identities', async () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    expect(alice.publicKeyHex).toHaveLength(64);
    expect(alice.keyId).toMatch(/^identity_[0-9a-f]{32}$/);

    const envelope = await encryptForRecipient('hello bob', bob, {
      senderKeyId: alice.keyId,
    });
    expect(envelope.alg).toBe('aes-256-gcm');
    expect(envelope.recipientKeyId).toBe(bob.keyId);
    expect(envelope.ciphertext).not.toContain('hello');

    expect(await decryptForRecipient(envelope, bob.secretKeyHex)).toBe('hello bob');
    await expect(decryptForRecipient(envelope, alice.secretKeyHex)).rejects.toThrow();
  });

  it('rejects tampered ciphertext, iv and recipient binding', async () => {
    const bob = generateIdentity();
    const envelope = await encryptForRecipient('secret', bob);

    const badCiphertext = {
      ...envelope,
      ciphertext: toBase64(fromBase64(envelope.ciphertext).reverse()),
    };
    await expect(decryptForRecipient(badCiphertext, bob.secretKeyHex)).rejects.toThrow();

    const badIv = { ...envelope, iv: toBase64(new Uint8Array(12)) };
    await expect(decryptForRecipient(badIv, bob.secretKeyHex)).rejects.toThrow();

    const rebound = { ...envelope, recipientKeyId: 'identity_someone_else' };
    await expect(decryptForRecipient(rebound, bob.secretKeyHex)).rejects.toThrow();
  });

  it('derives the same public key from a stored secret', () => {
    const identity = generateIdentity();
    const restored = identityFromSecret(identity.secretKeyHex);
    expect(restored.publicKeyHex).toBe(identity.publicKeyHex);
    expect(restored.keyId).toBe(identity.keyId);
  });

  it('wraps a group key per member and keeps it unreadable to others', async () => {
    const members = [generateIdentity(), generateIdentity(), generateIdentity()];
    const gmk = generateGroupMasterKey();
    const wrapped = await Promise.all(members.map((member) => wrapGroupKey(gmk, member, 2)));

    for (const [index, entry] of wrapped.entries()) {
      const unwrapped = await unwrapGroupKey(entry, members[index].secretKeyHex);
      expect(toBase64(unwrapped)).toBe(toBase64(gmk));
      expect(entry.gmkVersion).toBe(2);
      expect(entry.memberKeyId).toBe(members[index].keyId);
    }

    const outsider = generateIdentity();
    await expect(unwrapGroupKey(wrapped[0], outsider.secretKeyHex)).rejects.toThrow();
  });

  it('round-trips a group message and binds it to the group key generation', async () => {
    const member = generateIdentity();
    const gmk = generateGroupMasterKey();
    const envelope = await encryptForGroup('ship it', gmk, { groupId: 'group-1', version: 1 });

    expect(await decryptForGroup(envelope, gmk, { groupId: 'group-1' })).toBe('ship it');

    const otherGroup = { ...envelope };
    await expect(decryptForGroup(otherGroup, gmk, { groupId: 'group-2' })).rejects.toThrow();

    const rotated = generateGroupMasterKey();
    await expect(decryptForGroup(envelope, rotated, { groupId: 'group-1' })).rejects.toThrow();
    expect(member.publicKeyHex).toHaveLength(64);
  });

  it('encrypts attachment bytes and binds them to the media id', async () => {
    const bytes = new Uint8Array([0x00, 0x01, 0x02, 0xfe, 0xff, 0x10]);
    const sealed = await encryptFileBytes(bytes, 'media-1');

    expect(sealed.ciphertext).toBeInstanceOf(Uint8Array);
    expect(sealed.ciphertext.length).toBe(bytes.length + 16);
    expect(sealed.key).not.toContain('media-1');

    const opened = await decryptFileBytes(sealed.ciphertext, sealed.key, sealed.iv, 'media-1');
    expect([...opened]).toEqual([...bytes]);

    // A ciphertext is bound to its media id and cannot be replayed elsewhere.
    await expect(
      decryptFileBytes(sealed.ciphertext, sealed.key, sealed.iv, 'media-2'),
    ).rejects.toThrow();

    const tampered = new Uint8Array(sealed.ciphertext);
    tampered[0] ^= 0xff;
    await expect(decryptFileBytes(tampered, sealed.key, sealed.iv, 'media-1')).rejects.toThrow();
  });
});

describe('wire compatibility with the Node E2EE service', () => {
  it('decrypts a server-produced envelope with the browser identity', async () => {
    const client = generateIdentity();
    const envelope = serverEncrypt(
      'from the server',
      { keyId: client.keyId, publicKeyHex: client.publicKeyHex },
      { senderSessionKeyId: 'server', recipientSessionKeyId: client.keyId },
    );
    expect(await decryptForRecipient(envelope, client.secretKeyHex)).toBe('from the server');
  });

  it('produces envelopes the Node service can decrypt', async () => {
    const server = generateKeyPackage();
    const browser = generateIdentity();
    const envelope = await encryptForRecipient('from the browser', {
      keyId: 'identity_server',
      publicKeyHex: server.publicKeyHex,
    });

    const plaintext = decryptWithRecipient(envelope, { privateKeyHex: server.privateKeyHex });
    expect(plaintext.toString('utf8')).toBe('from the browser');
    expect(browser.publicKeyHex).toHaveLength(64);
  });

  it('signs messages the relay can verify', async () => {
    const browser = generateIdentity();
    const message = {
      messageId: 'msg-abc12345',
      threadId: 'thread_direct_a__b',
      senderId: 'user-1',
      type: 'text',
      createdAt: '2026-01-01T00:00:00Z',
      cipherBundle: {
        alg: 'aes-256-gcm',
        keyId: browser.keyId,
        recipientKeyId: 'identity_peer',
        ephemeralPublicKey: 'ab'.repeat(32),
        iv: 'aXY=',
        ciphertext: 'Y2lwaGVydGV4dA==',
      },
      metadata: { gmkVersion: 2, selfEnvelope: { ciphertext: 'c2VsZg==', iv: 'aXY=' } },
    };

    // The two implementations must build byte-identical canonical strings.
    expect(messageSigningPayload(message)).toBe(serverMessageSigningPayload(message));

    const signature = signMessage(message, browser.signingSecretKeyHex);
    expect(
      verifyEd25519Signature(
        messageSigningPayload(message),
        signature,
        browser.signingPublicKeyHex,
      ),
    ).toBe(true);

    // A field the relay sees differently must fail verification.
    const tampered = { ...message, createdAt: '2026-01-01T00:00:01Z' };
    expect(
      verifyEd25519Signature(
        messageSigningPayload(tampered),
        signature,
        browser.signingPublicKeyHex,
      ),
    ).toBe(false);
  });

  it('verifies stored history rows that expose the id as `id`', async () => {
    const browser = generateIdentity();
    const relayed = {
      messageId: 'msg-history-1',
      threadId: 'group-1',
      senderId: 'user-1',
      type: 'text',
      createdAt: '2026-01-01T00:00:00Z',
      cipherBundle: { alg: 'aes-256-gcm', iv: 'aXY=', ciphertext: 'Y2lwaGVy', gmkId: 'gmk_v1' },
      metadata: { gmkVersion: 1 },
    };
    const signature = signMessage(relayed, browser.signingSecretKeyHex);

    // The history API returns the same message with `id` instead of `messageId`.
    const row = { ...relayed, id: relayed.messageId };
    delete row.messageId;

    expect(messageSigningPayload(row)).toBe(messageSigningPayload(relayed));
    expect(
      verifyEd25519Signature(messageSigningPayload(row), signature, browser.signingPublicKeyHex),
    ).toBe(true);
  });

  it('signs group key distributions the relay can verify', async () => {
    const browser = generateIdentity();
    const distribution = {
      groupId: 'group-1',
      gmkVersion: 2,
      groupMasterKeyId: 'gmk_abc',
      createdAt: '2026-01-01T00:00:00Z',
      encryptedGMKByMember: [
        {
          memberKeyId: browser.keyId,
          wrappedGMK: 'd3JhcHBlZA==',
          iv: 'aXY=',
          ephemeralPublicKey: 'cd'.repeat(32),
          gmkVersion: 2,
        },
      ],
    };
    expect(browserGroupKeySigningPayload(distribution)).toBe(
      serverGroupKeySigningPayload(distribution),
    );

    const signature = signGroupKeyDistribution(distribution, browser.signingSecretKeyHex);
    expect(
      verifyEd25519Signature(
        serverGroupKeySigningPayload(distribution),
        signature,
        browser.signingPublicKeyHex,
      ),
    ).toBe(true);
  });

  it('unwraps a GMK distributed by the server and wraps one it can unwrap', async () => {
    const server = generateKeyPackage();
    const browser = generateIdentity();
    const gmk = generateGroupMasterKey();

    const distribution = distributeGroupMasterKey(
      'group-1',
      3,
      [{ memberKeyId: browser.keyId, recipientPublicKeyHex: browser.publicKeyHex }],
      Buffer.from(gmk),
    );
    const unwrapped = await unwrapGroupKey(
      distribution.encryptedGMKByMember[0],
      browser.secretKeyHex,
    );
    expect(toBase64(unwrapped)).toBe(toBase64(gmk));

    const wrappedForServer = await wrapGroupKey(
      gmk,
      {
        keyId: 'identity_server',
        publicKeyHex: server.publicKeyHex,
      },
      3,
    );
    const serverView = unwrapGroupMasterKey(wrappedForServer, server.privateKeyHex);
    expect(toBase64(new Uint8Array(serverView))).toBe(toBase64(gmk));
  });
});

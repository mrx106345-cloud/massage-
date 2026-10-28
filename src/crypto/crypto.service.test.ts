import { describe, it, expect } from 'vitest';
import {
  encryptForRecipient,
  decryptWithRecipient,
  generateKeyPackage,
  deriveSharedKey,
  publicKeyFor,
  distributeGroupMasterKey,
  unwrapGroupMasterKey,
  E2EE_ALGORITHM,
  E2EE_KEY_LENGTH,
  E2EE_IV_LENGTH,
} from '../services/crypto.service.js';
import { randomBytes } from 'node:crypto';

const chain = { senderSessionKeyId: 's1', recipientSessionKeyId: 'r1' };

describe('crypto service', () => {
  it('generateKeyPackage produces a real X25519 key pair', () => {
    const pkg = generateKeyPackage();
    expect(pkg.identityKeyId).toMatch(/^identity_[0-9a-f]+$/);
    expect(pkg.privateKeyHex).toHaveLength(E2EE_KEY_LENGTH * 2);
    expect(pkg.publicKeyHex).toHaveLength(E2EE_KEY_LENGTH * 2);
    expect(pkg.publicKeyHex).not.toBe(pkg.privateKeyHex);
    // The public key must be derivable from the private key.
    expect(publicKeyFor(pkg.privateKeyHex)).toBe(pkg.publicKeyHex);
  });

  it('derives an identical shared secret from both sides of an ECDH exchange', () => {
    const alice = generateKeyPackage();
    const bob = generateKeyPackage();
    const fromAlice = deriveSharedKey(alice.privateKeyHex, bob.publicKeyHex);
    const fromBob = deriveSharedKey(bob.privateKeyHex, alice.publicKeyHex);
    expect(fromAlice).toHaveLength(E2EE_KEY_LENGTH);
    expect(fromAlice.equals(fromBob)).toBe(true);
  });

  it('uses a different key per HKDF info label', () => {
    const alice = generateKeyPackage();
    const bob = generateKeyPackage();
    const a = deriveSharedKey(alice.privateKeyHex, bob.publicKeyHex, 'message-key');
    const b = deriveSharedKey(alice.privateKeyHex, bob.publicKeyHex, 'group-key:v1');
    expect(a.equals(b)).toBe(false);
  });

  it('encryptForRecipient returns a structured envelope', () => {
    const recipient = generateKeyPackage();
    const enc = encryptForRecipient(
      'hello world',
      { keyId: recipient.identityKeyId, publicKeyHex: recipient.publicKeyHex },
      chain,
    );
    expect(enc.ciphertext).toBeTruthy();
    expect(Buffer.from(enc.iv, 'base64')).toHaveLength(E2EE_IV_LENGTH);
    expect(enc.keyId).toBeTruthy();
    expect(enc.alg).toBe(E2EE_ALGORITHM);
    expect(enc.recipientKeyId).toBe(recipient.identityKeyId);
    expect(enc.ephemeralPublicKey).toHaveLength(64);
    expect(enc.senderChain).toEqual(chain);
    // The plaintext must never appear in the envelope.
    expect(enc.ciphertext).not.toContain('hello world');
  });

  it('round-trips a utf8 string for the matching private key', () => {
    const sender = generateKeyPackage();
    const recipient = generateKeyPackage();
    const plaintext = 'end-to-end encrypted payload';
    const env = encryptForRecipient(
      plaintext,
      { keyId: recipient.identityKeyId, publicKeyHex: recipient.publicKeyHex },
      { senderSessionKeyId: sender.identityKeyId, recipientSessionKeyId: recipient.identityKeyId },
    );
    const decrypted = decryptWithRecipient(env, recipient.privateKeyHex);
    expect(decrypted.toString('utf8')).toBe(plaintext);
  });

  it('round-trips binary payloads', () => {
    const recipient = generateKeyPackage();
    const payload = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff]);
    const env = encryptForRecipient(payload, recipient.publicKeyHex, chain);
    expect(decryptWithRecipient(env, Buffer.from(recipient.privateKeyHex, 'hex'))).toEqual(payload);
  });

  it('produces a fresh ephemeral key and IV for every message', () => {
    const recipient = generateKeyPackage();
    const a = encryptForRecipient('same', recipient.publicKeyHex, chain);
    const b = encryptForRecipient('same', recipient.publicKeyHex, chain);
    expect(a.ephemeralPublicKey).not.toBe(b.ephemeralPublicKey);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it('rejects a tampered ciphertext via GCM auth-tag verification', () => {
    const recipient = generateKeyPackage();
    const env = encryptForRecipient('secret', recipient.publicKeyHex, chain);
    const tampered = Buffer.from(env.ciphertext, 'base64');
    tampered[0] ^= 0xff;
    expect(() =>
      decryptWithRecipient(
        { ...env, ciphertext: tampered.toString('base64') },
        recipient.privateKeyHex,
      ),
    ).toThrow();
  });

  it('rejects decryption with the wrong private key', () => {
    const recipient = generateKeyPackage();
    const attacker = generateKeyPackage();
    const env = encryptForRecipient('secret', recipient.publicKeyHex, chain);
    expect(() => decryptWithRecipient(env, attacker.privateKeyHex)).toThrow();
  });

  it('binds the recipient key id as AAD (cannot be swapped)', () => {
    const recipient = generateKeyPackage();
    const env = encryptForRecipient('secret', recipient.publicKeyHex, chain);
    expect(() =>
      decryptWithRecipient({ ...env, recipientKeyId: 'someone-else' }, recipient.privateKeyHex),
    ).toThrow();
  });

  it('rejects a malformed recipient public key', () => {
    expect(() => encryptForRecipient('x', 'not-a-key', chain)).toThrow();
    expect(() => encryptForRecipient('x', 'aa'.repeat(16), chain)).toThrow(/X25519 public key/);
  });

  it('distributeGroupMasterKey wraps a GMK per member and each member can unwrap it', () => {
    const gmk = randomBytes(E2EE_KEY_LENGTH);
    const alice = generateKeyPackage();
    const bob = generateKeyPackage();
    const dist = distributeGroupMasterKey(
      'g1',
      1,
      [
        { memberKeyId: alice.identityKeyId, recipientPublicKeyHex: alice.publicKeyHex },
        { memberKeyId: bob.identityKeyId, recipientPublicKeyHex: bob.publicKeyHex },
      ],
      gmk,
    );

    expect(dist.groupId).toBe('g1');
    expect(dist.gmkVersion).toBe(1);
    expect(dist.encryptedGMKByMember).toHaveLength(2);
    expect(dist.encryptedGMKByMember.map((m) => m.memberKeyId)).toEqual([
      alice.identityKeyId,
      bob.identityKeyId,
    ]);

    for (const [index, pkg] of [alice, bob].entries()) {
      const unwrapped = unwrapGroupMasterKey(dist.encryptedGMKByMember[index], pkg.privateKeyHex);
      expect(unwrapped.equals(gmk)).toBe(true);
    }
  });

  it("does not let one member unwrap another member's GMK copy", () => {
    const gmk = randomBytes(E2EE_KEY_LENGTH);
    const alice = generateKeyPackage();
    const bob = generateKeyPackage();
    const dist = distributeGroupMasterKey(
      'g1',
      1,
      [{ memberKeyId: bob.identityKeyId, recipientPublicKeyHex: bob.publicKeyHex }],
      gmk,
    );
    expect(() => unwrapGroupMasterKey(dist.encryptedGMKByMember[0], alice.privateKeyHex)).toThrow();
  });

  it('rejects GMK distribution when a member has no published public key', () => {
    const gmk = randomBytes(E2EE_KEY_LENGTH);
    expect(() =>
      distributeGroupMasterKey('g1', 1, [{ memberKeyId: 'm1', recipientPublicKeyHex: '' }], gmk),
    ).toThrow(/missing an X25519 public key/);
  });

  it('assigns a unique groupMasterKeyId per call', () => {
    const gmk = randomBytes(E2EE_KEY_LENGTH);
    const bob = generateKeyPackage();
    const members = [{ memberKeyId: bob.identityKeyId, recipientPublicKeyHex: bob.publicKeyHex }];
    const a = distributeGroupMasterKey('g1', 1, members, gmk);
    const b = distributeGroupMasterKey('g1', 1, members, gmk);
    expect(a.groupMasterKeyId).not.toBe(b.groupMasterKeyId);
    expect(a.encryptedGMKByMember[0].wrappedGMK).not.toBe(b.encryptedGMKByMember[0].wrappedGMK);
  });
});

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from 'node:crypto';

/** E2EE primitives used by the messaging pipeline (RFC 001 key management). */

export const E2EE_ALGORITHM = 'aes-256-gcm';
export const E2EE_KEY_LENGTH = 32; // bytes
export const E2EE_IV_LENGTH = 12; // bytes (96-bit GCM IV)
export const E2EE_TAG_LENGTH = 16; // bytes (128-bit GCM auth tag)
export const E2EE_NONCE_SEPARATION = true; // ciphertext is body || tag

export type ContentType = 'text' | 'image' | 'video' | 'audio' | 'file';
export type EncryptionKeyId = string;

/** A "sender chain" record used to route the correct ciphertext. */
export interface SessionChain {
  senderSessionKeyId: string;
  recipientSessionKeyId: string;
}

/** Public half of a recipient identity, as published via the pre-key bundle. */
export interface RecipientKey {
  keyId: string;
  publicKeyHex: string;
}

/** A Key Package for a newly registered user (RFC 001 §2). */
export interface KeyPackage {
  identityKeyId: string;
  privateKeyHex: string;
  publicKeyHex: string;
}

// DER prefixes for raw X25519 keys (RFC 8410).
const SPKI_X25519_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

// DER prefixes for raw Ed25519 keys (RFC 8410).
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function publicKeyFromRaw(raw: Buffer) {
  if (raw.length !== 32) throw new Error('X25519 public key must be 32 bytes');
  return createPublicKey({
    key: Buffer.concat([SPKI_X25519_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function privateKeyFromRaw(raw: Buffer) {
  if (raw.length !== 32) throw new Error('X25519 private key must be 32 bytes');
  return createPrivateKey({
    key: Buffer.concat([PKCS8_X25519_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });
}

function toRawPublic(key: ReturnType<typeof createPublicKey>): Buffer {
  const der = key.export({ format: 'der', type: 'spki' }) as Buffer;
  return der.subarray(der.length - 32);
}

function toRawPrivate(key: ReturnType<typeof createPrivateKey>): Buffer {
  const der = key.export({ format: 'der', type: 'pkcs8' }) as Buffer;
  return der.subarray(der.length - 32);
}

function ed25519PublicKeyFromRaw(raw: Buffer) {
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function ed25519PrivateKeyFromRaw(raw: Buffer) {
  if (raw.length !== 32) throw new Error('Ed25519 private key must be 32 bytes');
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });
}

/** Generate an Ed25519 signing key pair (raw hex halves). */
export function generateSigningKeyPair(): { publicKeyHex: string; privateKeyHex: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyHex: toRawPublic(publicKey).toString('hex'),
    privateKeyHex: toRawPrivate(privateKey).toString('hex'),
  };
}

/** Sign a UTF-8 canonical payload with an Ed25519 private key. */
export function signPayload(payload: string, privateKeyHex: string): string {
  const key = ed25519PrivateKeyFromRaw(Buffer.from(privateKeyHex, 'hex'));
  return sign(null, Buffer.from(payload, 'utf8'), key).toString('base64');
}

/** Verify an Ed25519 detached signature. Returns false for malformed input. */
export function verifyEd25519Signature(
  payload: string,
  signatureBase64: string,
  publicKeyHex: string,
): boolean {
  try {
    if (!/^[0-9a-f]{64}$/i.test(publicKeyHex)) return false;
    const signature = Buffer.from(signatureBase64, 'base64');
    if (signature.length !== 64) return false;
    const key = ed25519PublicKeyFromRaw(Buffer.from(publicKeyHex, 'hex'));
    return verify(null, Buffer.from(payload, 'utf8'), key, signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Signed payloads
// ---------------------------------------------------------------------------
//
// Canonical strings are duplicated in `public/js/crypto.js`. Keep the field
// order and separators identical: both sides must reconstruct the exact bytes
// the sender signed, and the server verifies the same payload before storing.

export interface MessageSigningInput {
  messageId: string;
  threadId: string;
  senderId: string;
  type: string;
  createdAt: string;
  cipherBundle: Record<string, unknown>;
  metadata?: Record<string, unknown> | null;
}

function signedField(value: unknown): string {
  return value === null || value === undefined ? '' : String(value);
}

export function messageSigningPayload(input: MessageSigningInput): string {
  const bundle = input.cipherBundle ?? {};
  const metadata = input.metadata ?? {};
  const self = (metadata.selfEnvelope ?? {}) as Record<string, unknown>;
  return [
    'aegis-message-v1',
    signedField(input.messageId),
    signedField(input.threadId),
    signedField(input.senderId),
    signedField(input.type),
    signedField(input.createdAt),
    signedField(bundle.alg),
    signedField(bundle.keyId),
    signedField(bundle.recipientKeyId),
    signedField(bundle.gmkId),
    signedField(bundle.ephemeralPublicKey),
    signedField(bundle.iv),
    signedField(bundle.ciphertext),
    signedField(metadata.gmkVersion),
    signedField(metadata.mediaId),
    signedField(self.ciphertext),
    signedField(self.iv),
    signedField(self.ephemeralPublicKey),
    signedField(self.recipientKeyId),
  ].join('\n');
}

export interface GroupKeySigningInput {
  groupId: string;
  gmkVersion: number;
  groupMasterKeyId: string;
  createdAt: string;
  encryptedGMKByMember: Array<Record<string, unknown>>;
}

export function groupKeySigningPayload(input: GroupKeySigningInput): string {
  const lines = [
    'aegis-group-key-v1',
    signedField(input.groupId),
    signedField(input.gmkVersion),
    signedField(input.groupMasterKeyId),
    signedField(input.createdAt),
  ];
  for (const entry of input.encryptedGMKByMember ?? []) {
    lines.push(
      [
        signedField(entry.memberKeyId),
        signedField(entry.wrappedGMK),
        signedField(entry.iv),
        signedField(entry.ephemeralPublicKey),
        signedField(entry.gmkVersion),
      ].join('|'),
    );
  }
  return lines.join('\n');
}

/** Generate an X25519 identity key pair with a stable key id. */
export function generateKeyPackage(): KeyPackage {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const publicKeyHex = toRawPublic(publicKey).toString('hex');
  return {
    identityKeyId: `identity_${randomBytes(16).toString('hex')}`,
    privateKeyHex: toRawPrivate(privateKey).toString('hex'),
    publicKeyHex,
  };
}

/** Derive the raw 32-byte public key for a private key (hex in, hex out). */
export function publicKeyFor(privateKeyHex: string): string {
  const privateKey = privateKeyFromRaw(Buffer.from(privateKeyHex, 'hex'));
  return toRawPublic(createPublicKey(privateKey)).toString('hex');
}

/** ECDH + HKDF-SHA256 with an algorithm-scoped info label. */
export function deriveSharedKey(
  privateKeyRaw: Buffer | string,
  publicKeyRaw: Buffer | string,
  info = 'message-key',
): Buffer {
  const privateKey = privateKeyFromRaw(
    typeof privateKeyRaw === 'string' ? Buffer.from(privateKeyRaw, 'hex') : privateKeyRaw,
  );
  const publicKey = publicKeyFromRaw(
    typeof publicKeyRaw === 'string' ? Buffer.from(publicKeyRaw, 'hex') : publicKeyRaw,
  );
  const sharedSecret = diffieHellman({ privateKey, publicKey });
  const salt = Buffer.alloc(0);
  const label = Buffer.concat([Buffer.from('aegis-e2ee-v1'), Buffer.from(`:${info}`, 'utf8')]);
  return Buffer.from(hkdfSync('sha256', sharedSecret, salt, label, E2EE_KEY_LENGTH));
}

// ---------------------------------------------------------------------------
// Message encryption
// ---------------------------------------------------------------------------

export interface EncryptedMessage {
  ciphertext: string; // base64(body || 16-byte GCM tag)
  iv: string; // base64
  keyId: string; // per-message key id
  alg: string;
  recipientKeyId: string;
  senderChain: SessionChain;
  /** Ephemeral X25519 public key (hex) used for this message's ECDH. */
  ephemeralPublicKey: string;
  metadata?: Record<string, unknown>;
}

function normalizeRecipient(recipient: RecipientKey | string): RecipientKey {
  if (typeof recipient === 'string') {
    if (!/^[0-9a-f]{64}$/i.test(recipient)) {
      throw new Error(
        'recipient must be an X25519 public key (64 hex chars) or a { keyId, publicKeyHex } object',
      );
    }
    return { keyId: `x25519_${recipient.slice(0, 16)}`, publicKeyHex: recipient };
  }
  return recipient;
}

function seal(plaintext: Buffer, key: Buffer, aad: Buffer): { iv: Buffer; ciphertext: Buffer } {
  const iv = randomBytes(E2EE_IV_LENGTH);
  const cipher = createCipheriv(E2EE_ALGORITHM, key, iv);
  cipher.setAAD(aad);
  const body = cipher.update(plaintext);
  cipher.final();
  return { iv, ciphertext: Buffer.concat([body, cipher.getAuthTag()]) };
}

function open(ciphertext: Buffer, key: Buffer, iv: Buffer, aad: Buffer): Buffer {
  if (ciphertext.length < E2EE_TAG_LENGTH) throw new Error('ciphertext too short');
  const body = ciphertext.subarray(0, ciphertext.length - E2EE_TAG_LENGTH);
  const tag = ciphertext.subarray(ciphertext.length - E2EE_TAG_LENGTH);
  const decipher = createDecipheriv(E2EE_ALGORITHM, key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

/**
 * Encrypt plaintext for a single recipient.
 *   1. Generate an ephemeral X25519 key pair for this message.
 *   2. ECDH with the recipient's published identity key, then HKDF-SHA256.
 *   3. Seal the payload with AES-256-GCM; the recipient key id is bound as AAD
 *      so a ciphertext cannot be replayed to a different recipient.
 */
export function encryptForRecipient(
  plaintext: Buffer | string,
  recipient: RecipientKey | string,
  senderChain: SessionChain,
  extraMetadata?: Record<string, unknown>,
): EncryptedMessage {
  const target = normalizeRecipient(recipient);
  const recipientPublicKey = Buffer.from(target.publicKeyHex, 'hex');
  if (recipientPublicKey.length !== E2EE_KEY_LENGTH) {
    throw new Error('recipient public key must be 32 bytes');
  }

  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralPublicKey = toRawPublic(ephemeral.publicKey);
  const ephemeralPrivateKey = toRawPrivate(ephemeral.privateKey);
  const messageKey = deriveSharedKey(ephemeralPrivateKey, recipientPublicKey, 'message-key');

  const plaintextBuffer =
    typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
  const { iv, ciphertext } = seal(plaintextBuffer, messageKey, Buffer.from(target.keyId, 'utf8'));

  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    keyId: randomUUID(),
    alg: E2EE_ALGORITHM,
    recipientKeyId: target.keyId,
    senderChain,
    ephemeralPublicKey: ephemeralPublicKey.toString('hex'),
    metadata: extraMetadata,
  };
}

/** Decrypt an envelope produced by {@link encryptForRecipient}. */
export function decryptWithRecipient(
  encrypted: EncryptedMessage,
  recipientPrivateKey: Buffer | string | KeyPackage,
): Buffer {
  if (encrypted.alg !== E2EE_ALGORITHM) {
    throw new Error(`unsupported algorithm: ${encrypted.alg}`);
  }
  const privateKeyHex =
    typeof recipientPrivateKey === 'string'
      ? recipientPrivateKey
      : Buffer.isBuffer(recipientPrivateKey)
        ? recipientPrivateKey.toString('hex')
        : recipientPrivateKey.privateKeyHex;

  if (!encrypted.ephemeralPublicKey) {
    throw new Error('envelope is missing the ephemeral public key');
  }

  const messageKey = deriveSharedKey(privateKeyHex, encrypted.ephemeralPublicKey, 'message-key');

  return open(
    Buffer.from(encrypted.ciphertext, 'base64'),
    messageKey,
    Buffer.from(encrypted.iv, 'base64'),
    Buffer.from(encrypted.recipientKeyId, 'utf8'),
  );
}

// ---------------------------------------------------------------------------
// Group Master Key (GMK) distribution
// ---------------------------------------------------------------------------

export interface WrappedGroupKey {
  memberKeyId: string;
  /** base64(body || tag) of the wrapped GMK. */
  wrappedGMK: string;
  iv: string;
  ephemeralPublicKey: string;
  gmkVersion: number;
}
export interface GroupKeyDist {
  groupId: string;
  groupMasterKeyId: string;
  encryptedGMKByMember: WrappedGroupKey[];
  gmkVersion: number;
}
export interface GroupMemberKey {
  memberKeyId: string;
  /** X25519 public key (hex) published by the member's device. */
  recipientPublicKeyHex: string;
}

/** Wrap the GMK once per member. Each member can only unwrap their own copy. */
export function distributeGroupMasterKey(
  groupId: string,
  gmkVersion: number,
  members: GroupMemberKey[],
  gmkSecret: Buffer,
): GroupKeyDist {
  if (gmkSecret.length !== E2EE_KEY_LENGTH) {
    throw new Error(`GMK must be ${E2EE_KEY_LENGTH} bytes`);
  }

  const encryptedGMKByMember = members.map((member) => {
    if (!member.recipientPublicKeyHex) {
      throw new Error(`member ${member.memberKeyId} is missing an X25519 public key`);
    }
    const ephemeral = generateKeyPairSync('x25519');
    const ephemeralPublicKey = toRawPublic(ephemeral.publicKey);
    const wrappingKey = deriveSharedKey(
      toRawPrivate(ephemeral.privateKey),
      Buffer.from(member.recipientPublicKeyHex, 'hex'),
      `group-key:v${gmkVersion}`,
    );
    const { iv, ciphertext } = seal(
      gmkSecret,
      wrappingKey,
      Buffer.from(member.memberKeyId, 'utf8'),
    );
    return {
      memberKeyId: member.memberKeyId,
      wrappedGMK: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      ephemeralPublicKey: ephemeralPublicKey.toString('hex'),
      gmkVersion,
    };
  });

  return {
    groupId,
    groupMasterKeyId: `gmk_${randomUUID()}`,
    encryptedGMKByMember,
    gmkVersion,
  };
}

/** Member-side unwrap of their own GMK copy. */
export function unwrapGroupMasterKey(
  wrapped: WrappedGroupKey,
  memberPrivateKeyHex: string | KeyPackage,
): Buffer {
  const privateKeyHex =
    typeof memberPrivateKeyHex === 'string'
      ? memberPrivateKeyHex
      : memberPrivateKeyHex.privateKeyHex;
  const wrappingKey = deriveSharedKey(
    privateKeyHex,
    wrapped.ephemeralPublicKey,
    `group-key:v${wrapped.gmkVersion}`,
  );
  return open(
    Buffer.from(wrapped.wrappedGMK, 'base64'),
    wrappingKey,
    Buffer.from(wrapped.iv, 'base64'),
    Buffer.from(wrapped.memberKeyId, 'utf8'),
  );
}

// ---------------------------------------------------------------------------
// Self E2EE context (RFC 001 §1 + §3)
// ---------------------------------------------------------------------------

/**
 * GET /api/v1/crypto/keys/self
 */
export async function getSelfE2EEContext(
  _req: { userId?: string | null },
  res: Res,
): Promise<void> {
  const userId = _req.userId;
  if (!userId) {
    asRes(res).status(401).json({ error: 'unauthorized' });
    return;
  }

  const rows = await selectAll(
    'crypto_key',
    { owner_id: userId, status: 'active' },
    999,
    [
      'key_id',
      'x25519_public',
      'curve25519_public',
      'ed25519_public',
      'public_key_pem',
      'created_at',
    ],
    { column: 'created_at', direction: 'desc' },
  );

  const published: Array<{
    keyId: string;
    publicKey: string | null;
    x25519_public: string | null;
    curve25519_public: string | null;
    signingPublicKey: string | null;
    ed25519_public: string | null;
    createdAt: string | null;
  }> = rows.map((r) => {
    const publicKey: string | null =
      r.public_key_pem != null
        ? String(r.public_key_pem)
        : r.x25519_public != null
          ? String(r.x25519_public)
          : null;
    const signingPublicKey = r.ed25519_public != null ? String(r.ed25519_public) : null;
    return {
      keyId: String(r.key_id),
      publicKey,
      x25519_public: r.x25519_public != null ? String(r.x25519_public) : null,
      curve25519_public: r.curve25519_public != null ? String(r.curve25519_public) : null,
      signingPublicKey,
      ed25519_public: signingPublicKey,
      createdAt: r.created_at != null ? String(r.created_at) : null,
    };
  });

  if (published.length === 0) {
    logger.info(
      { userId, action: 'e2ee-no-keys' },
      'GET /api/v1/crypto/keys/self -> 404 (no published keys for user)',
    );
    asRes(res).status(404).json({
      error: 'no E2EE keys published for this account yet',
      hint: 'publish an X25519 identity key through the socket channel, then retry GET /api/v1/crypto/keys/self',
    });
    return;
  }

  asRes(res).json({ keys: published });
}

/**
 * POST /api/v1/crypto/keys/self
 */
export async function provisionSelfE2EEContext(
  _req: { userId?: string | null },
  res: Res,
): Promise<void> {
  const userId = _req.userId;
  if (!userId) {
    asRes(res).status(401).json({ error: 'unauthorized' });
    return;
  }

  asRes(res).status(501).json({
    error: 'key provisioning is client-generated',
    hint: 'generate an X25519 key pair locally, publish the public half through the socket channel, then call GET /api/v1/crypto/keys/self',
  });
}

import { selectAll } from '../db/index.js';
import { logger } from '../utils/logger.js';

type Res = {
  status: (code: number) => {
    json: (body: unknown) => void;
  };
} & { json: (body: unknown) => void; status: (code: number) => Res };

function asRes(res: unknown): Res {
  return res as Res;
}

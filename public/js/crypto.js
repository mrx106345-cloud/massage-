/**
 * Client-side E2EE primitives.
 *
 * Wire-compatible with `src/services/crypto.service.ts`:
 *   - X25519 ECDH (tweetnacl scalarMult) with an ephemeral key per envelope
 *   - HKDF-SHA256, empty salt, info = "aegis-e2ee-v1:<label>"
 *   - AES-256-GCM, 12-byte IV, ciphertext = body || 16-byte tag, base64
 *   - the recipient key id is bound as AAD
 *
 * Group messages are sealed with a random 32-byte Group Master Key. Each member
 * receives the GMK wrapped with the same construction (label `group-key:v<n>`,
 * AAD = member key id), so the server only ever sees opaque blobs.
 *
 * `nacl` is loaded by a classic <script> tag as `window.nacl`; in Node tests it
 * can be injected with `setNacl(require('tweetnacl'))`.
 */

const ALG = 'aes-256-gcm';
const VERSION_LABEL = 'aegis-e2ee-v1';
const IV_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;

let naclRef = globalThis.nacl ?? null;

export function setNacl(nacl) {
  naclRef = nacl;
}

function nacl() {
  if (!naclRef) throw new Error('tweetnacl is not loaded');
  return naclRef;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(value) {
  return encoder.encode(value);
}

export function fromUtf8(bytes) {
  return decoder.decode(bytes);
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error('invalid hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function fromBase64(value) {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function keyIdFor(publicKeyHex) {
  return `identity_${publicKeyHex.slice(0, 32)}`;
}

function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Derive the Ed25519 signing key deterministically from the X25519 identity
 * secret. Existing browser identities therefore gain a stable signing key
 * without a storage migration, and two tabs cannot disagree about it.
 */
function signingPairFromSecret(secretKeyBytes) {
  const seed = nacl()
    .hash(concatBytes(utf8('aegis-signing-key-v1'), secretKeyBytes))
    .slice(0, 32);
  return nacl().sign.keyPair.fromSeed(seed);
}

function requireCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto is unavailable; serve the app over HTTPS or localhost');
  }
  return globalThis.crypto;
}

/**
 * A device identity: raw X25519 key material for encryption, plus an Ed25519
 * key for signing messages and group-key distributions. The signing key is
 * derived from the X25519 secret so existing identities migrate implicitly.
 */
export function generateIdentity() {
  const pair = nacl().box.keyPair();
  const publicKeyHex = toHex(pair.publicKey);
  const signing = signingPairFromSecret(pair.secretKey);
  return {
    publicKeyHex,
    secretKeyHex: toHex(pair.secretKey),
    signingPublicKeyHex: toHex(signing.publicKey),
    signingSecretKeyHex: toHex(signing.secretKey),
    keyId: keyIdFor(publicKeyHex),
  };
}

export async function safetyNumberIdentity(identity) {
  if (!identity) return null;
  return safetyNumber(identity, {
    publicKeyHex: identity.publicKeyHex,
    signingPublicKeyHex: identity.signingPublicKeyHex,
  });
}

/** Rebuild an identity (public halves + key id) from a stored X25519 secret. */
export function identityFromSecret(secretKeyHex) {
  const secretKey = fromHex(secretKeyHex);
  if (secretKey.length !== KEY_BYTES) throw new Error('identity secret key must be 32 bytes');
  const publicKey = nacl().scalarMult.base(secretKey);
  const publicKeyHex = toHex(publicKey);
  const signing = signingPairFromSecret(secretKey);
  return {
    publicKeyHex,
    secretKeyHex,
    signingPublicKeyHex: toHex(signing.publicKey),
    signingSecretKeyHex: toHex(signing.secretKey),
    keyId: keyIdFor(publicKeyHex),
  };
}

async function deriveBytes(sharedSecret, label) {
  const subtle = requireCrypto().subtle;
  const baseKey = await subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const info = utf8(`${VERSION_LABEL}:${label}`);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

async function aesKey(rawKey, usages) {
  return requireCrypto().subtle.importKey('raw', rawKey, 'AES-GCM', false, usages);
}

async function seal(plaintextBytes, rawKey, aadText) {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await requireCrypto().subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(aadText) },
    await aesKey(rawKey, ['encrypt']),
    plaintextBytes,
  );
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

async function open(ciphertextBytes, rawKey, ivBytes, aadText) {
  if (ciphertextBytes.length <= TAG_BYTES) throw new Error('ciphertext too short');
  const plaintext = await requireCrypto().subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes, additionalData: utf8(aadText) },
    await aesKey(rawKey, ['decrypt']),
    ciphertextBytes,
  );
  return new Uint8Array(plaintext);
}

export function newMessageKeyId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return toHex(randomBytes(16));
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------
//
// These canonical strings must stay byte-for-byte identical to
// `src/services/crypto.service.ts`; the server verifies the same payload it
// receives before storing a message.

export function messageSigningPayload(message) {
  const field = (value) => (value === null || value === undefined ? '' : String(value));
  const bundle = message?.cipherBundle ?? {};
  const metadata = message?.metadata ?? {};
  const self = metadata.selfEnvelope ?? {};
  // Stored history rows expose the id as `id`; relayed payloads use
  // `messageId`. Both must rebuild the same signed string, or every message
  // re-read from the server would look tampered with.
  const messageId = message?.messageId ?? message?.id;
  return [
    'aegis-message-v1',
    field(messageId),
    field(message?.threadId),
    field(message?.senderId),
    field(message?.type),
    field(message?.createdAt),
    field(bundle.alg),
    field(bundle.keyId),
    field(bundle.recipientKeyId),
    field(bundle.gmkId),
    field(bundle.ephemeralPublicKey),
    field(bundle.iv),
    field(bundle.ciphertext),
    field(metadata.gmkVersion),
    field(metadata.mediaId),
    field(self.ciphertext),
    field(self.iv),
    field(self.ephemeralPublicKey),
    field(self.recipientKeyId),
  ].join('\n');
}

export function signMessage(message, signingSecretKeyHex) {
  const signature = nacl().sign.detached(
    utf8(messageSigningPayload(message)),
    fromHex(signingSecretKeyHex),
  );
  return toBase64(signature);
}

export function verifyMessageSignature(message, signatureBase64, signingPublicKeyHex) {
  try {
    if (!/^[0-9a-f]{64}$/i.test(signingPublicKeyHex)) return false;
    const signature = fromBase64(signatureBase64);
    if (signature.length !== 64) return false;
    return nacl().sign.detached.verify(
      utf8(messageSigningPayload(message)),
      signature,
      fromHex(signingPublicKeyHex),
    );
  } catch {
    return false;
  }
}

export function groupKeySigningPayload(distribution) {
  const field = (value) => (value === null || value === undefined ? '' : String(value));
  const lines = [
    'aegis-group-key-v1',
    field(distribution?.groupId),
    field(distribution?.gmkVersion),
    field(distribution?.groupMasterKeyId),
    field(distribution?.createdAt),
  ];
  for (const entry of distribution?.encryptedGMKByMember ?? []) {
    lines.push(
      [
        field(entry.memberKeyId),
        field(entry.wrappedGMK),
        field(entry.iv),
        field(entry.ephemeralPublicKey),
        field(entry.gmkVersion),
      ].join('|'),
    );
  }
  return lines.join('\n');
}

export function signGroupKeyDistribution(distribution, signingSecretKeyHex) {
  const signature = nacl().sign.detached(
    utf8(groupKeySigningPayload(distribution)),
    fromHex(signingSecretKeyHex),
  );
  return toBase64(signature);
}

export function verifyGroupKeyDistribution(distribution, signatureBase64, signingPublicKeyHex) {
  try {
    if (!/^[0-9a-f]{64}$/i.test(signingPublicKeyHex)) return false;
    const signature = fromBase64(signatureBase64);
    if (signature.length !== 64) return false;
    return nacl().sign.detached.verify(
      utf8(groupKeySigningPayload(distribution)),
      signature,
      fromHex(signingPublicKeyHex),
    );
  } catch {
    return false;
  }
}

/**
 * A 60-digit safety number derived from both parties' public keys. Sorting the
 * two entries makes the value identical on both devices. This is a manual
 * verification aid, not a substitute for key transparency.
 */
export async function safetyNumber(identityA, identityB) {
  const entries = [identityA, identityB]
    .map((identity) => ({
      keyId: String(identity?.keyId ?? ''),
      x25519: String(identity?.publicKeyHex ?? '').toLowerCase(),
      ed25519: String(identity?.signingPublicKeyHex ?? '').toLowerCase(),
    }))
    .sort((a, b) => a.keyId.localeCompare(b.keyId));
  const payload = [
    'aegis-safety-v1',
    ...entries.map((entry) => `${entry.keyId}|${entry.x25519}|${entry.ed25519}`),
  ].join('\n');
  const digest = new Uint8Array(await requireCrypto().subtle.digest('SHA-256', utf8(payload)));
  let digits = '';
  for (let i = 0; i < digest.length && digits.length < 60; i += 1) {
    digits += String(digest[i]).padStart(3, '0');
  }
  return digits.slice(0, 60).match(/.{5}/g).join(' ');
}

/**
 * Encrypt for one recipient identity. `recipient` is `{ keyId, publicKeyHex }`
 * exactly as returned by GET /api/v1/users/:id/public-key.
 */
export async function encryptForRecipient(plaintext, recipient, options = {}) {
  if (!recipient?.publicKeyHex || recipient.publicKeyHex.length !== 64) {
    throw new Error('recipient public key must be 32 bytes of hex');
  }
  const ephemeral = nacl().box.keyPair();
  const shared = nacl().scalarMult(ephemeral.secretKey, fromHex(recipient.publicKeyHex));
  const messageKey = await deriveBytes(shared, 'message-key');
  const { iv, ciphertext } = await seal(utf8(plaintext), messageKey, recipient.keyId);

  return {
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv),
    keyId: newMessageKeyId(),
    alg: ALG,
    recipientKeyId: recipient.keyId,
    senderChain: options.senderChain ?? {
      senderSessionKeyId: options.senderKeyId ?? 'client',
      recipientSessionKeyId: recipient.keyId,
    },
    ephemeralPublicKey: toHex(ephemeral.publicKey),
  };
}

/** Decrypt a message envelope addressed to this identity. */
export async function decryptForRecipient(envelope, secretKeyHex) {
  if (!envelope || envelope.alg !== ALG) throw new Error('unsupported envelope');
  if (!envelope.ephemeralPublicKey) throw new Error('envelope is missing an ephemeral key');

  const shared = nacl().scalarMult(fromHex(secretKeyHex), fromHex(envelope.ephemeralPublicKey));
  const messageKey = await deriveBytes(shared, 'message-key');
  try {
    const plaintext = await open(
      fromBase64(envelope.ciphertext),
      messageKey,
      fromBase64(envelope.iv),
      envelope.recipientKeyId,
    );
    return fromUtf8(plaintext);
  } catch {
    throw new Error('message could not be decrypted with this identity');
  }
}

// ---------------------------------------------------------------------------
// Group keys
// ---------------------------------------------------------------------------

export function generateGroupMasterKey() {
  return randomBytes(KEY_BYTES);
}

/** Wrap the GMK for one member (server-compatible `WrappedGroupKey`). */
export async function wrapGroupKey(gmkBytes, member, version) {
  if (!member?.publicKeyHex || !member.keyId) throw new Error('member identity is incomplete');
  if (gmkBytes.length !== KEY_BYTES) throw new Error('group key must be 32 bytes');

  const ephemeral = nacl().box.keyPair();
  const shared = nacl().scalarMult(ephemeral.secretKey, fromHex(member.publicKeyHex));
  const wrappingKey = await deriveBytes(shared, `group-key:v${version}`);
  const { iv, ciphertext } = await seal(gmkBytes, wrappingKey, member.keyId);

  return {
    memberKeyId: member.keyId,
    wrappedGMK: toBase64(ciphertext),
    iv: toBase64(iv),
    ephemeralPublicKey: toHex(ephemeral.publicKey),
    gmkVersion: version,
  };
}

/** Unwrap this member's GMK copy. */
export async function unwrapGroupKey(wrapped, secretKeyHex) {
  if (!wrapped?.ephemeralPublicKey) throw new Error('wrapped key is incomplete');
  const shared = nacl().scalarMult(fromHex(secretKeyHex), fromHex(wrapped.ephemeralPublicKey));
  const wrappingKey = await deriveBytes(shared, `group-key:v${wrapped.gmkVersion}`);
  try {
    const gmk = await open(
      fromBase64(wrapped.wrappedGMK),
      wrappingKey,
      fromBase64(wrapped.iv),
      wrapped.memberKeyId,
    );
    return gmk;
  } catch {
    throw new Error('this group key was not wrapped for this identity');
  }
}

/**
 * A 60-digit safety number for a single identity, independent of a conversation.
 * Usable before any other party joins the room.
 */
export async function safetyNumberSelf(identity) {
  if (!identity?.publicKeyHex) return null;
  const entry = {
    keyId: identity.keyId,
    x25519: identity.publicKeyHex.toLowerCase(),
    ed25519: identity.signingPublicKeyHex.toLowerCase(),
  };
  return safetyNumber(entry, entry);
}

/** Group payload AAD is scoped to both the group and the key generation. */
function groupAad(groupId, version) {
  return `gmk:${version}:${groupId}`;
}

// ---------------------------------------------------------------------------
// Media (file) encryption
// ---------------------------------------------------------------------------
//
// Files are sealed with a one-off AES-256-GCM key before they leave the
// browser. The key and IV travel inside the encrypted message envelope, never
// in server-visible metadata; the media id is bound as AAD so a ciphertext
// cannot be replayed under another attachment.

function mediaAad(mediaId) {
  if (typeof mediaId !== 'string' || mediaId.length === 0) {
    throw new Error('media id is required');
  }
  return `aegis-media-v1:${mediaId}`;
}

/** Encrypt raw file bytes. Returns ciphertext plus the key/IV to seal inside the message. */
export async function encryptFileBytes(bytes, mediaId) {
  if (!(bytes instanceof Uint8Array)) throw new Error('file bytes must be a Uint8Array');
  const key = randomBytes(KEY_BYTES);
  const { iv, ciphertext } = await seal(bytes, key, mediaAad(mediaId));
  return { ciphertext, key: toBase64(key), iv: toBase64(iv) };
}

/** Decrypt a file downloaded from the media endpoint. */
export async function decryptFileBytes(ciphertext, keyBase64, ivBase64, mediaId) {
  const key = fromBase64(keyBase64);
  if (key.length !== KEY_BYTES) throw new Error('media key must be 32 bytes');
  return open(ciphertext, key, fromBase64(ivBase64), mediaAad(mediaId));
}

export async function encryptForGroup(plaintext, gmkBytes, { groupId, version }) {
  if (gmkBytes.length !== KEY_BYTES) throw new Error('group key must be 32 bytes');
  const { iv, ciphertext } = await seal(utf8(plaintext), gmkBytes, groupAad(groupId, version));
  return {
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv),
    keyId: newMessageKeyId(),
    alg: ALG,
    gmkId: `gmk_v${version}`,
    gmkVersion: version,
  };
}

export async function decryptForGroup(envelope, gmkBytes, { groupId }) {
  const version = Number(envelope?.gmkVersion ?? String(envelope?.gmkId ?? '').replace(/\D/g, ''));
  if (!version) throw new Error('envelope is missing its group key version');
  try {
    const plaintext = await open(
      fromBase64(envelope.ciphertext),
      gmkBytes,
      fromBase64(envelope.iv),
      groupAad(groupId, version),
    );
    return fromUtf8(plaintext);
  } catch {
    throw new Error('message could not be decrypted with the current group key');
  }
}

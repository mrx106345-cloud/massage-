/**
 * TOTP (RFC 6238) two-factor authentication.
 *
 * Implemented with node:crypto only — HMAC-SHA1, 30 second steps, 6 digits —
 * which is what Google Authenticator, Authy, 1Password and iOS/Android
 * authenticators expect. Verification accepts a ±1 step window for clock skew
 * and compares codes in constant time.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;

export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function base32Decode(input: string): Buffer {
  const normalized = input.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error('invalid base32 character');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** 160-bit secret, base32 encoded (the size recommended by RFC 4226). */
export function generateTotpSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

export function hotp(secret: string, counter: number, digits = TOTP_DIGITS): string {
  const key = base32Decode(secret);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', key).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

export function totpCode(secret: string, atMs = Date.now(), period = TOTP_PERIOD_SECONDS): string {
  return hotp(secret, Math.floor(atMs / 1000 / period));
}

/** Constant-time verification with a ±`window` step tolerance. */
export function verifyTotp(
  secret: string,
  code: string,
  options: { window?: number; atMs?: number; period?: number } = {},
): boolean {
  if (typeof code !== 'string') return false;
  const candidate = code.replace(/\s/g, '');
  if (!/^\d{6}$/.test(candidate)) return false;
  const { window = 1, atMs = Date.now(), period = TOTP_PERIOD_SECONDS } = options;
  const counter = Math.floor(atMs / 1000 / period);
  const expected = Buffer.from(candidate, 'utf8');
  let matched = false;
  for (let offset = -window; offset <= window; offset += 1) {
    const generated = Buffer.from(hotp(secret, counter + offset), 'utf8');
    // Compare every candidate to keep timing independent of which window hit.
    if (generated.length === expected.length && timingSafeEqual(generated, expected)) {
      matched = true;
    }
  }
  return matched;
}

/** otpauth:// URI for authenticator apps (rendered as a QR code client-side). */
export function otpauthUrl(secret: string, account: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

const BACKUP_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/** Human-readable single-use recovery codes (e.g. "K7QF2-9WXPD"). */
export function generateBackupCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const raw = randomBytes(10);
    let code = '';
    for (let j = 0; j < 10; j += 1) {
      code += BACKUP_CODE_ALPHABET[raw[j] % BACKUP_CODE_ALPHABET.length];
      if (j === 4) code += '-';
    }
    codes.push(code);
  }
  return codes;
}

export function normalizeBackupCode(code: string): string {
  return code.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

export function hashBackupCode(code: string): string {
  return createHash('sha256').update(normalizeBackupCode(code)).digest('hex');
}

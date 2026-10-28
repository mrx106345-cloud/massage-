/**
 * Two-factor recovery codes.
 *
 * Codes are shown once at enrolment and stored as SHA-256 hashes. Each code can
 * be redeemed a single time; redemption is a conditional update so two parallel
 * login attempts cannot both use the same code.
 */

import { randomUUID } from 'node:crypto';
import { countRows, deleteRows, insertRow, selectOne, updateRows } from '../db/index.js';
import { generateBackupCodes, hashBackupCode } from './totp.service.js';

export async function issueBackupCodes(userId: string, count = 10): Promise<string[]> {
  const codes = generateBackupCodes(count);
  const now = new Date().toISOString();
  await deleteRows('totp_backup_code', { user_id: userId });
  for (const code of codes) {
    await insertRow('totp_backup_code', {
      id: randomUUID(),
      user_id: userId,
      code_hash: hashBackupCode(code),
      used_at: null,
      created_at: now,
    });
  }
  return codes;
}

/** Returns true exactly once per valid code. */
export async function consumeBackupCode(userId: string, code: string): Promise<boolean> {
  if (!code) return false;
  const row = await selectOne('totp_backup_code', {
    user_id: userId,
    code_hash: hashBackupCode(code),
    used_at: null,
  });
  if (!row) return false;
  const updated = await updateRows(
    'totp_backup_code',
    { id: String(row.id), used_at: null },
    { used_at: new Date().toISOString() },
  );
  return updated > 0;
}

export async function deleteBackupCodes(userId: string): Promise<void> {
  await deleteRows('totp_backup_code', { user_id: userId });
}

export async function countUnusedBackupCodes(userId: string): Promise<number> {
  return countRows('totp_backup_code', { user_id: userId, used_at: { _isNull: true } });
}

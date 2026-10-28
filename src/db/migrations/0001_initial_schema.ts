/**
 * Migration 0001: initial schema.
 *
 * The DDL lives in `createSchema()` so the migration CLI, boot-time bootstrap
 * (`AUTO_MIGRATE`) and the in-memory test setup cannot drift apart. The
 * migration itself is just the versioned entry point.
 *
 *   npm run migrate:dev          -> create/upgrade the schema
 *   npm run migrate:dev -- down  -> drop every table
 */

import 'dotenv/config';
import { createSchema, execute } from '../index.js';

/** Child tables first so foreign keys (when enabled) never block the drop. */
const TABLES = [
  'audit_log',
  'totp_backup_code',
  'auth_token',
  'media_file',
  'offline_queue_item',
  'report',
  'invite',
  'session',
  'crypto_key',
  'message',
  'group_member',
  'group',
  'direct_message_thread',
  'migration',
  'maintenance',
  'user',
];

export async function up(): Promise<void> {
  await createSchema();
}

export async function down(): Promise<void> {
  for (const table of TABLES) {
    await execute(`DROP TABLE IF EXISTS "${table}"`);
  }
}

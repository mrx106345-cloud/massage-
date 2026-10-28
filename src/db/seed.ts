/**
 * Development seed data.
 *
 *   npm run db:seed
 *
 * Creates the schema if needed, clears the demo tables and inserts three users,
 * a direct thread and a group. Safe to re-run; never use against production.
 */

import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { createSchema, deleteRows, insertRow, shutdown } from './index.js';

const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

async function clearDemoData(): Promise<void> {
  const tables = [
    'offline_queue_item',
    'report',
    'invite',
    'session',
    'auth_token',
    'totp_backup_code',
    'audit_log',
    'media_file',
    'crypto_key',
    'message',
    'group_member',
    'group',
    'direct_message_thread',
    'user',
  ];
  for (const table of tables) {
    await deleteRows(table, {});
  }
}

async function main(): Promise<void> {
  const email = process.env.SEED_EMAIL || 'demo@example.com';
  const password = process.env.SEED_PASSWORD || 'demo1234';
  const username = process.env.SEED_USERNAME || 'demo_user';

  if (process.env.NODE_ENV === 'production') {
    throw new Error('refusing to seed a production database');
  }
  if (password.length < 8) {
    throw new Error('SEED_PASSWORD must be at least 8 characters');
  }

  await createSchema();
  await clearDemoData();

  const createdAt = now();
  const passwordHash = bcrypt.hashSync(password, 12);

  const users = [
    { username, email },
    { username: 'alice', email: 'alice@example.com' },
    { username: 'bob', email: 'bob@example.com' },
  ];
  const ids = new Map<string, string>();

  for (const user of users) {
    const id = randomUUID();
    ids.set(user.username, id);
    await insertRow('user', {
      id,
      username: user.username,
      email: user.email.toLowerCase(),
      password_hash: passwordHash,
      avatar_url: null,
      token_version: 0,
      is_online: false,
      email_verified: true,
      totp_secret: null,
      totp_enabled: false,
      created_at: createdAt,
      updated_at: createdAt,
    });
  }

  // Direct thread between the demo user and alice.
  await insertRow('direct_message_thread', {
    id: randomUUID(),
    user_a_id: ids.get(username),
    user_b_id: ids.get('alice'),
    last_message_id: null,
    last_read_message_id: null,
    last_read_at: null,
    last_updated_at: createdAt,
    unread_count_a: 0,
    unread_count_b: 0,
    created_at: createdAt,
    updated_at: createdAt,
  });

  // A small public group with all three users.
  const groupId = randomUUID();
  await insertRow('group', {
    id: groupId,
    name: 'Sprint 2026',
    admin_id: ids.get(username),
    is_private: false,
    gm_locked: false,
    gm_version: 1,
    created_at: createdAt,
    updated_at: createdAt,
  });

  for (const [member, isAdmin] of [
    [username, true],
    ['alice', false],
    ['bob', false],
  ] as const) {
    await insertRow('group_member', {
      id: randomUUID(),
      group_id: groupId,
      user_id: ids.get(member),
      joined_at: createdAt,
      is_admin: isAdmin,
      joined_via_invite: false,
      invite_token: null,
      last_read_message_id: null,
      last_read_at: null,
      status: 'active',
    });
  }

  console.log('Seed complete.');
  for (const user of users) {
    console.log(`  ${user.username} <${user.email}> / ${password}`);
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await shutdown();
  });

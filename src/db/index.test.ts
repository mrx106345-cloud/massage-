import { describe, it, expect, beforeEach } from 'vitest';
import { db, selectOne, selectAll, execute, resetDb, createSchema } from './index.js';

describe('db raw-SQL helpers (in-memory SQLite)', () => {
  beforeEach(async () => {
    resetDb();
    // An in-memory better-sqlite3 DB created by `resetDb()` is empty, so
    // create the schema each time so the SELECT/INSERT helpers have tables to
    // talk to.
    await createSchema();
  });

  it('selectOne returns null for a missing row', async () => {
    const row = await selectOne('user', { username: 'nobody' });
    expect(row).toBeNull();
  });

  it('selectOne returns the row for an existing key', async () => {
    await execute(
      "INSERT INTO user (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('u1','alice','a@b.com','h',0,false,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    );
    const row = await selectOne('user', { username: 'alice' });
    expect(row).not.toBeNull();
    expect(row?.username).toBe('alice');
    expect(row?.email).toBe('a@b.com');
  });

  it('selectOne with explicit columns returns only those columns', async () => {
    await execute(
      "INSERT INTO user (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('u2','bob','b@b.com','h',0,false,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    );
    const row = await selectOne('user', { username: 'bob' }, ['id', 'username']);
    expect(row).not.toBeNull();
    expect(Object.keys(row ?? {})).toEqual(expect.arrayContaining(['id', 'username']));
    expect(row?.password_hash).toBeUndefined();
  });

  it('selectAll returns an empty array when nothing matches', async () => {
    const rows = await selectAll('user', { username: { _like: '%nobody%' } });
    expect(rows).toEqual([]);
  });

  it('selectAll returns all matching rows', async () => {
    await execute(
      "INSERT INTO user (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('u3','carol','c@c.com','h',0,false,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    );
    await execute(
      "INSERT INTO user (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('u4','carol2','c2@c.com','h',0,false,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    );
    const rows = await selectAll('user', { username: { _like: 'carol%' } });
    expect(rows.length).toBeGreaterThanOrEqual(2);
    expect(rows.map((r) => r.username)).toContain('carol');
  });

  it('execute runs a raw statement without throwing', async () => {
    await execute(
      "INSERT INTO user (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('u5','dave','d@d.com','h',0,false,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    );
    const row = await selectOne('user', { username: 'dave' });
    expect(row).not.toBeNull();
  });

  it('selectOne with _or matches either condition', async () => {
    await execute(
      "INSERT INTO user (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('u6','eve','eve@b.com','h',0,false,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    );
    const row = await selectOne('user', { _or: [{ username: 'eve' }, { email: 'eve@b.com' }] });
    expect(row).not.toBeNull();
    expect(row?.username).toBe('eve');
  });

  it('selectOne with _or only matches the given values', async () => {
    await execute(
      "INSERT INTO user (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('u9','zoe','zoe@b.com','h',0,false,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    );
    const hit = await selectOne('user', { _or: [{ username: 'zoe' }, { email: 'zoe@b.com' }] });
    expect(hit?.username).toBe('zoe');
    const miss = await selectOne('user', {
      _or: [{ username: 'nobody' }, { email: 'nobody@b.com' }],
    });
    expect(miss).toBeNull();
  });

  it('selectOne with _in matches any included value', async () => {
    await execute(
      "INSERT INTO user (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('u7','frank','f@b.com','h',0,false,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    );
    const row = await selectOne('user', { id: { _in: ['u7', 'u8'] } });
    expect(row).not.toBeNull();
    expect(row?.username).toBe('frank');
  });
});

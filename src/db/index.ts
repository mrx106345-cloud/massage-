import { createRequire } from 'node:module';
import { Kysely, DummyDriver, DefaultQueryCompiler, PostgresDialect } from 'kysely';
import type { Database } from './types.js';
import { createMemoryDialect } from './sqlite.js';
import BetterSqlite3, { type Database as BetterSqlite3Database } from 'better-sqlite3';

const env = process.env.NODE_ENV ?? 'development';
const requireLocal = createRequire(import.meta.url);

let dbInstance: Kysely<Database> | null = null;
let rawSqlite: BetterSqlite3Database | null = null;

// Minimal structural type for the `pg` pool; `pg` ships no type definitions of
// its own and we only need `query`/`end`.
interface PgPool {
  query(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
  end(): Promise<void>;
}
let pgPool: PgPool | null = null;

function createDialect() {
  const driver = process.env.DB_DRIVER ?? (process.env.DATABASE_URL ? 'postgres' : 'memory');

  if (driver === 'memory' || driver === 'file') {
    const path = driver === 'file' ? (process.env.DB_PATH ?? 'data/aegis.db') : ':memory:';
    rawSqlite = new BetterSqlite3(path, { readonly: false });
    rawSqlite.pragma('journal_mode = WAL');
    rawSqlite.pragma('foreign_keys = ON');
    return createMemoryDialect({ database: rawSqlite });
  }

  if (driver === 'postgres') {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) {
      throw new Error('DB_DRIVER=postgres requires DATABASE_URL to be set');
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const pg: any = requireLocal('pg');
    const pool: PgPool = new pg.Pool({
      connectionString,
      max: Number(process.env.DB_POOL_MAX ?? 10),
    });
    pgPool = pool;
    return new PostgresDialect({ pool: pool as never });
  }

  return {
    createDriver: () => new DummyDriver(),
    createQueryCompiler: () => new DefaultQueryCompiler(),
    createAdapter: () => ({}) as never,
    createIntrospector: () => ({}) as never,
  } as never;
}

export function getDb(): Kysely<Database> {
  if (!dbInstance) {
    dbInstance = new Kysely<Database>({
      dialect: createDialect(),
      log:
        env === 'development' && process.env.DB_LOG === 'true'
          ? (info: unknown) => console.log(info)
          : undefined,
    });
  }
  return dbInstance;
}

export function resetDb(): void {
  const previous = dbInstance;
  if (previous) void previous.destroy().catch(() => undefined);
  try {
    rawSqlite?.close();
  } catch {
    // already closed
  }
  rawSqlite = null;
  pgPool = null;
  dbInstance = null;
}

/**
 * A stable handle on the current Kysely instance. Every property is forwarded
 * to `getDb()`, so a `resetDb()` (tests, migration CLI) is visible to modules
 * that captured `db` at import time.
 */
export const db: Kysely<Database> = new Proxy({} as Kysely<Database>, {
  get(_target, prop) {
    const instance = getDb();
    const value = (instance as unknown as Record<string | symbol, unknown>)[prop];
    return typeof value === 'function' ? value.bind(instance) : value;
  },
}) as Kysely<Database>;

export async function shutdown(): Promise<void> {
  const instance = dbInstance;
  dbInstance = null;
  if (instance) await instance.destroy().catch(() => undefined);
  if (pgPool) await pgPool.end().catch(() => undefined);
  pgPool = null;
  try {
    rawSqlite?.close();
  } catch {
    // already closed
  }
  rawSqlite = null;
}

type WhereCondition = Record<string, unknown>;

/**
 * better-sqlite3 refuses to bind booleans; Postgres expects them. Normalise
 * values for the active driver so services can stay driver-agnostic.
 */
function coerceValue(value: unknown): unknown {
  if (rawSqlite && typeof value === 'boolean') return value ? 1 : 0;
  return value;
}

function coerceValues(values: Record<string, unknown>): Record<string, unknown> {
  if (!rawSqlite) return values;
  const normalized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(values)) normalized[key] = coerceValue(value);
  return normalized;
}

/**
 * Apply a where map to a Kysely builder. Kysely builders are immutable, so the
 * (possibly new) builder must be returned and reassigned by the caller.
 */
function applyWhere<T>(q: T, where: WhereCondition): T {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let builder = q as any;
  for (const [col, val] of Object.entries(where)) {
    if (col === '_or' && Array.isArray(val)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      builder = builder.where((eb: any) => {
        const groups = (val as Record<string, unknown>[]).map((sub) => {
          const terms = Object.entries(sub).map(([c, v]) => condition(eb, c, v));
          return terms.length === 1 ? terms[0] : eb.and(terms);
        });
        return groups.length === 1 ? groups[0] : eb.or(groups);
      });
      continue;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    builder = builder.where((eb: any) => condition(eb, col, val));
  }
  return builder as T;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function condition(eb: any, col: string, val: unknown) {
  if (val === null) {
    // SQL equality never matches NULL; callers use null to mean "IS NULL".
    return eb(col as any, 'is', null);
  }
  if (val && typeof val === 'object' && !Array.isArray(val)) {
    const ops = val as Record<string, unknown>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const c = col as any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const v = (input: unknown) => coerceValue(input) as any;
    if ('_in' in ops) return eb(c, 'in', (ops._in as unknown[]).map(coerceValue));

    if ('_notIn' in ops) return eb(c, 'not in', (ops._notIn as unknown[]).map(coerceValue));
    if ('_like' in ops) return eb(c, 'like', ops._like);
    if ('_ilike' in ops) return eb(c, 'ilike', ops._ilike);
    if ('_ne' in ops) return eb(c, '!=', v(ops._ne));
    if ('_gt' in ops) return eb(c, '>', v(ops._gt));
    if ('_gte' in ops) return eb(c, '>=', v(ops._gte));
    if ('_lt' in ops) return eb(c, '<', v(ops._lt));
    if ('_lte' in ops) return eb(c, '<=', v(ops._lte));
    if ('_isNull' in ops) return ops._isNull ? eb(c, 'is', null) : eb(c, 'is not', null);
    if ('_notNull' in ops) return ops._notNull ? eb(c, 'is not', null) : eb(c, 'is', null);
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return eb(col as any, '=', coerceValue(val));
}

export async function selectOne(
  table: string,
  where: WhereCondition = {},
  columns: string[] = [],
): Promise<Record<string, unknown> | null> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stmt = getDb().selectFrom(table as never) as any;
  stmt = applyWhere(stmt, where);
  stmt = columns.length ? stmt.select(columns.map((c) => c as never)) : stmt.selectAll();
  const rows = (await stmt.limit(1).execute()) as Record<string, unknown>[];
  return rows[0] ?? null;
}

export async function selectAll(
  table: string,
  where: WhereCondition = {},
  limit = 100,
  columns: string[] = [],
  orderBy?: { column: string; direction?: 'asc' | 'desc' },
): Promise<Record<string, unknown>[]> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stmt = getDb().selectFrom(table as never) as any;
  stmt = applyWhere(stmt, where);
  stmt = columns.length ? stmt.select(columns.map((c) => c as never)) : stmt.selectAll();
  if (orderBy) stmt = stmt.orderBy(orderBy.column as never, orderBy.direction ?? 'asc');
  return (await stmt.limit(limit).execute()) as Record<string, unknown>[];
}

export async function countRows(table: string, where: WhereCondition = {}): Promise<number> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stmt = getDb().selectFrom(table as never) as any;
  stmt = applyWhere(stmt, where);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const row = (await stmt.select((eb: any) => eb.fn.countAll().as('count')).executeTakeFirst()) as
    { count: string | number } | undefined;
  return Number(row?.count ?? 0);
}

export async function insertRow(table: string, values: Record<string, unknown>): Promise<void> {
  await getDb()
    .insertInto(table as never)
    .values(coerceValues(values) as never)
    .execute();
}

export async function updateRows(
  table: string,
  where: WhereCondition,
  values: Record<string, unknown>,
): Promise<number> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stmt = (getDb().updateTable(table as never) as any).set(coerceValues(values));
  stmt = applyWhere(stmt, where);
  const result = await stmt.executeTakeFirst();
  return Number(result?.numUpdatedRows ?? result?.numAffectedRows ?? 0);
}

export async function deleteRows(table: string, where: WhereCondition): Promise<number> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stmt = getDb().deleteFrom(table as never) as any;
  stmt = applyWhere(stmt, where);
  const result = await stmt.executeTakeFirst();
  return Number(result?.numDeletedRows ?? result?.numAffectedRows ?? 0);
}

function toPgPlaceholders(sqlQuery: string): string {
  let index = 0;
  return sqlQuery.replace(/\?/g, () => `$${++index}`);
}

/**
 * Run a raw statement. Use `?` placeholders and pass values in `params` — never
 * interpolate user input into `sqlQuery`.
 */
export async function execute(sqlQuery: string, params: unknown[] = []): Promise<void> {
  // Lazily create the connection so `execute()` also works when it is the first
  // database call (e.g. right after resetDb()).
  if (!rawSqlite && !pgPool) getDb();
  if (rawSqlite) {
    if (params.length) rawSqlite.prepare(sqlQuery).run(...(params as never[]));
    else rawSqlite.exec(sqlQuery);
    return;
  }
  if (pgPool) {
    await pgPool.query(toPgPlaceholders(sqlQuery), params);
  }
}

/** Run a raw SELECT. Mirrors {@link execute} for reads. */
export async function rawQuery(
  sqlQuery: string,
  params: unknown[] = [],
): Promise<Record<string, unknown>[]> {
  if (!rawSqlite && !pgPool) getDb();
  if (rawSqlite) {
    return rawSqlite.prepare(sqlQuery).all(...(params as never[])) as Record<string, unknown>[];
  }
  if (pgPool) {
    const result = await pgPool.query(toPgPlaceholders(sqlQuery), params);
    return result.rows;
  }
  return [];
}

async function columnExists(table: string, column: string): Promise<boolean> {
  if (rawSqlite) {
    const rows = (await rawQuery(`PRAGMA table_info("${table}")`)) as Array<{ name: string }>;
    return rows.some((r) => r.name === column);
  }
  if (pgPool) {
    const rows = await rawQuery(
      'SELECT column_name FROM information_schema.columns WHERE table_name = ? AND column_name = ?',
      [table, column],
    );
    return rows.length > 0;
  }
  return false;
}

const SCHEMA_UP = [
  `CREATE TABLE IF NOT EXISTS "user" (id VARCHAR(36) PRIMARY KEY, username VARCHAR(64) NOT NULL UNIQUE, email VARCHAR(255) NOT NULL UNIQUE, password_hash TEXT NOT NULL, avatar_url TEXT, bio TEXT, token_version INTEGER NOT NULL DEFAULT 0, is_online BOOLEAN NOT NULL DEFAULT FALSE, email_verified BOOLEAN NOT NULL DEFAULT FALSE, totp_secret TEXT, totp_enabled BOOLEAN NOT NULL DEFAULT FALSE, created_at VARCHAR(36) NOT NULL, updated_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS direct_message_thread (id VARCHAR(36) PRIMARY KEY, user_a_id VARCHAR(36) NOT NULL, user_b_id VARCHAR(36) NOT NULL, last_message_id VARCHAR(36), last_read_message_id VARCHAR(36), last_read_at VARCHAR(36), last_updated_at VARCHAR(36), unread_count_a INTEGER NOT NULL DEFAULT 0, unread_count_b INTEGER NOT NULL DEFAULT 0, created_at VARCHAR(36) NOT NULL, updated_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS "group" (id VARCHAR(36) PRIMARY KEY, name VARCHAR(128), admin_id VARCHAR(36) NOT NULL, is_private BOOLEAN NOT NULL DEFAULT FALSE, gm_locked BOOLEAN, gm_version INTEGER, created_at VARCHAR(36) NOT NULL, updated_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS group_member (id VARCHAR(36) PRIMARY KEY, group_id VARCHAR(36) NOT NULL, user_id VARCHAR(36) NOT NULL, joined_at VARCHAR(36) NOT NULL, is_admin BOOLEAN NOT NULL DEFAULT FALSE, joined_via_invite BOOLEAN NOT NULL DEFAULT FALSE, invite_token VARCHAR(64), last_read_message_id VARCHAR(36), last_read_at VARCHAR(36), status VARCHAR(16) NOT NULL DEFAULT 'active')`,
  `CREATE TABLE IF NOT EXISTS message (id VARCHAR(36) PRIMARY KEY, thread_id VARCHAR(36) NOT NULL, sender_id VARCHAR(36) NOT NULL, parent_id VARCHAR(36), content_type VARCHAR(32) NOT NULL, content TEXT, encrypted_content TEXT, encryption_alg VARCHAR(32), encryption_key_id VARCHAR(64), gmk_id VARCHAR(64), metadata TEXT, signature TEXT, signature_key_id VARCHAR(64), status VARCHAR(16) NOT NULL DEFAULT 'sent', delivery_receipts TEXT, created_at VARCHAR(36) NOT NULL, updated_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS media_file (id VARCHAR(36) PRIMARY KEY, message_id VARCHAR(36), owner_id VARCHAR(36) NOT NULL, original_name VARCHAR(255) NOT NULL, content_type VARCHAR(128) NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0, storage_key TEXT NOT NULL, upload_url TEXT, download_url TEXT, upload_status VARCHAR(16) NOT NULL DEFAULT 'pending', upload_error TEXT, media_type VARCHAR(16) NOT NULL DEFAULT 'file', duration_seconds INTEGER, width INTEGER, height INTEGER, thumb_url TEXT, created_at VARCHAR(36) NOT NULL, updated_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS crypto_key (id VARCHAR(36) PRIMARY KEY, owner_id VARCHAR(36) NOT NULL, key_type VARCHAR(32) NOT NULL, key_id VARCHAR(64) NOT NULL, public_key_pem TEXT, private_key_pem TEXT, x25519_public TEXT, curve25519_public TEXT, ed25519_public TEXT, usage VARCHAR(32) NOT NULL, expires_at VARCHAR(36), status VARCHAR(16) NOT NULL DEFAULT 'active', created_at VARCHAR(36) NOT NULL, updated_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS session (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, token TEXT NOT NULL, token_version INTEGER NOT NULL, ip_address TEXT, user_agent TEXT, is_anonymous BOOLEAN, created_at VARCHAR(36) NOT NULL, updated_at VARCHAR(36) NOT NULL, expires_at VARCHAR(36) NOT NULL, revoked_at VARCHAR(36))`,
  `CREATE TABLE IF NOT EXISTS auth_token (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, type VARCHAR(32) NOT NULL, token_hash VARCHAR(64) NOT NULL, expires_at VARCHAR(36) NOT NULL, consumed_at VARCHAR(36), created_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS totp_backup_code (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, code_hash VARCHAR(64) NOT NULL, used_at VARCHAR(36), created_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS audit_log (id VARCHAR(36) PRIMARY KEY, actor_id VARCHAR(36), action VARCHAR(64) NOT NULL, target_type VARCHAR(32), target_id VARCHAR(36), ip_address TEXT, user_agent TEXT, metadata TEXT, created_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS invite (id VARCHAR(36) PRIMARY KEY, group_id VARCHAR(36) NOT NULL, token VARCHAR(64) NOT NULL UNIQUE, inviter_id VARCHAR(36) NOT NULL, invited_email VARCHAR(255), invited_username VARCHAR(64), status VARCHAR(16) NOT NULL DEFAULT 'pending', expires_at VARCHAR(36), created_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS report (id VARCHAR(36) PRIMARY KEY, reported_by_id VARCHAR(36) NOT NULL, reported_user_id VARCHAR(36) NOT NULL, group_id VARCHAR(36), message_id VARCHAR(36), reason VARCHAR(32) NOT NULL, details TEXT, status VARCHAR(16) NOT NULL DEFAULT 'open', created_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS offline_queue_item (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, channel_type VARCHAR(16) NOT NULL, channel_id VARCHAR(36) NOT NULL, message_id VARCHAR(36) NOT NULL, payload TEXT NOT NULL, enqueued_at VARCHAR(36) NOT NULL, delivered_at VARCHAR(36), status VARCHAR(16) NOT NULL DEFAULT 'queued')`,
  `CREATE TABLE IF NOT EXISTS maintenance (id VARCHAR(36) PRIMARY KEY, key VARCHAR(64), value TEXT, updated_at VARCHAR(36) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS migration (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, batch INTEGER NOT NULL, migration_time VARCHAR(36) NOT NULL, executed_at VARCHAR(36) NOT NULL)`,
].join(';');

// Columns added after the original schema shipped. Existing file/Postgres
// databases get them through ALTER TABLE; fresh databases already have them.
const COLUMN_MIGRATIONS: Array<[table: string, column: string, definition: string]> = [
  ['user', 'email_verified', 'BOOLEAN NOT NULL DEFAULT FALSE'],
  ['user', 'totp_secret', 'TEXT'],
  ['user', 'totp_enabled', 'BOOLEAN NOT NULL DEFAULT FALSE'],
  ['session', 'revoked_at', 'VARCHAR(36)'],
  ['crypto_key', 'ed25519_public', 'TEXT'],
  ['message', 'signature', 'TEXT'],
  ['message', 'signature_key_id', 'VARCHAR(64)'],
];

// Indexes backing the lookup patterns used by the services. IF NOT EXISTS keeps
// schema bootstrap idempotent on both SQLite and PostgreSQL.
const INDEXES = [
  'CREATE INDEX IF NOT EXISTS idx_message_thread ON message(thread_id)',
  'CREATE INDEX IF NOT EXISTS idx_message_sender ON message(sender_id)',
  'CREATE INDEX IF NOT EXISTS idx_group_member_group ON group_member(group_id)',
  'CREATE INDEX IF NOT EXISTS idx_group_member_user ON group_member(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_crypto_key_owner ON crypto_key(owner_id)',
  'CREATE INDEX IF NOT EXISTS idx_session_token ON session(token)',
  'CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_auth_token_hash ON auth_token(token_hash)',
  'CREATE INDEX IF NOT EXISTS idx_auth_token_user ON auth_token(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id)',
  'CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_id)',
  'CREATE INDEX IF NOT EXISTS idx_offline_queue_status ON offline_queue_item(status)',
];

export async function createSchema(): Promise<void> {
  for (const statement of SCHEMA_UP.split(';')) {
    const trimmed = statement.trim();
    if (!trimmed) continue;
    await execute(trimmed);
  }

  for (const [table, column, definition] of COLUMN_MIGRATIONS) {
    if (await columnExists(table, column)) continue;
    await execute(`ALTER TABLE "${table}" ADD COLUMN ${column} ${definition}`);
  }

  for (const index of INDEXES) {
    await execute(index);
  }
}

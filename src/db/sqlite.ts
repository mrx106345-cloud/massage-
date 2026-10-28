import {
  type Dialect,
  SqliteDriver,
  SqliteQueryCompiler,
  SqliteAdapter,
  SqliteIntrospector,
} from 'kysely';
import Database, { type Database as DatabaseType } from 'better-sqlite3';

// Kysely's SqliteDriver accepts a `database` config value that is either a
// sqlite3 connection object or a factory. better-sqlite3's `Database`
// instance implements the sqlite3 connection interface (exec/prepare/
// transaction/close), so we pass it directly.

export interface BetterSqlite3DialectConfig {
  database: DatabaseType | string;
  wal?: boolean;
}

export function createBetterSqlite3Dialect(config: BetterSqlite3DialectConfig): Dialect {
  const db =
    typeof config.database === 'string'
      ? new Database(config.database, { readonly: false })
      : config.database;
  // Re-apply pragmas if we provided the database directly
  if (config.wal !== false) {
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
  }

  return {
    createDriver: () => new SqliteDriver({ database: db as any }),
    createQueryCompiler: () => new SqliteQueryCompiler(),
    createAdapter: () => new SqliteAdapter(),
    createIntrospector: (qb) => new SqliteIntrospector(qb),
  };
}

/** Shorthand for an in-memory better-sqlite3 database. */
export function createMemoryDialect(config?: { database?: DatabaseType | string; wal?: boolean }) {
  return createBetterSqlite3Dialect({
    database: config?.database ?? ':memory:',
    wal: config?.wal !== false,
  });
}

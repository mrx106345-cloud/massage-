/**
 * Test utilities and fixtures for industrial-grade testing.
 *
 * Provides:
 * - Factory functions for creating realistic test data
 * - Helper functions for setting up/tearing down test databases
 * - Assertion helpers for common patterns
 * - Type-safe request/response factories
 */

import { resetDb, createSchema, execute } from '../db/index.js';
import type { Request, Response } from 'express';

// ---------------------------------------------------------------------------
// Test lifecycle helpers
// ---------------------------------------------------------------------------

export async function setupTestDb(): Promise<void> {
  await resetDb();
  await createSchema();
}

export async function teardownTestDb(): Promise<void> {
  // Clean up is handled by resetDb in beforeEach
}

// ---------------------------------------------------------------------------
// Factories for realistic test data
// ---------------------------------------------------------------------------

export interface UserFactoryInput {
  id?: string;
  username?: string;
  email?: string;
  password?: string;
  tokenVersion?: number;
}

export function createUserFactory(input: UserFactoryInput = {}) {
  const id = input.id ?? `user-${Math.random().toString(36).slice(2, 11)}`;
  const username = input.username ?? `user-${Math.random().toString(36).slice(2, 8)}`;
  const email = input.email ?? `${username}@example.com`;
  const password = input.password ?? 'SecurePass123!';
  const tokenVersion = input.tokenVersion ?? 0;

  return {
    id,
    username,
    email,
    password,
    tokenVersion,
  };
}

export interface GroupFactoryInput {
  id?: string;
  name?: string;
  adminId?: string;
  isPrivate?: boolean;
}

export function createGroupFactory(input: GroupFactoryInput = {}) {
  const id = input.id ?? `group-${Math.random().toString(36).slice(2, 11)}`;
  const name = input.name ?? `Group ${Math.random().toString(36).slice(2, 6)}`;
  const adminId = input.adminId ?? `admin-${Math.random().toString(36).slice(2, 11)}`;
  const isPrivate = input.isPrivate ?? false;

  return {
    id,
    name,
    adminId,
    isPrivate,
  };
}

// ---------------------------------------------------------------------------
// Request/Response factories (migrated from test files)
// ---------------------------------------------------------------------------

export interface MakeReqOptions {
  body?: Record<string, unknown>;
  params?: Record<string, string>;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  userId?: string;
  method?: string;
  url?: string;
}

export function makeReq(options: MakeReqOptions = {}): Request {
  const {
    body = {},
    params = {},
    query = {},
    headers = {},
    userId,
    method = 'POST',
    url = '/api/v1/test',
  } = options;

  return {
    body,
    params,
    query,
    headers: {
      ...headers,
      authorization: headers.authorization ?? undefined,
      'content-type': headers['content-type'] ?? 'application/json',
    },
    socket: { remoteAddress: '127.0.0.1' },
    method,
    url,
    userId,
    get(name: string) {
      return (this as any).headers[name.toLowerCase()] ?? undefined;
    },
  } as unknown as Request;
}

export interface MakeResOptions {
  statusCode?: number;
  headers?: Record<string, string>;
}

export function makeRes(options: MakeResOptions = {}): Response {
  const { statusCode = 200, headers = {} } = options;

  const res: any = {
    statusCode,
    headers,
    _json: undefined,
    _headers: { ...headers },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this._json = payload;
      return this;
    },
    setHeader(k: string, v: string) {
      this._headers[k] = v;
      this.headers[k] = v;
      return this;
    },
    getHeader(k: string) {
      return this._headers[k] ?? undefined;
    },
    type(contentType: string) {
      this.setHeader('content-type', contentType);
      return this;
    },
    sendStatus(code: number) {
      this.statusCode = code;
      return this;
    },
  };

  return res as unknown as Response;
} // ---------------------------------------------------------------------------
// Database seeding helpers for integration tests
// ---------------------------------------------------------------------------

export interface SeedTestDataInput {
  users?: Array<{ username: string; email: string; password: string }>;
  groups?: Array<{ name: string; adminId: string; isPrivate?: boolean }>;
}

export async function seedTestData(input: SeedTestDataInput = {}) {
  const { users = [], groups = [] } = input;

  // Insert users
  for (const user of users) {
    const userId = `user-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    await execute(
      `INSERT INTO "user" (id, username, email, password_hash, token_version, is_online, created_at, updated_at) VALUES ('${userId}', '${user.username}', '${user.email}', 'hashed', 0, 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
    );
  }

  // Insert groups
  for (const group of groups) {
    const groupId = `group-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    await execute(
      `INSERT INTO "group" (id, name, admin_id, is_private, gm_locked, gm_version, created_at, updated_at) VALUES ('${groupId}', '${group.name}', '${group.adminId}', ${group.isPrivate ? 1 : 0}, 0, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
    );
  }
}

// ---------------------------------------------------------------------------
// Test data cleanup (for beforeEach/afterEach)
// ---------------------------------------------------------------------------

export async function clearAllTables() {
  const tables = [
    'offline_queue_item',
    'invite',
    'report',
    'message',
    'group_member',
    'group',
    'session',
    'crypto_key',
    'user',
    'direct_message_thread',
    'maintenance',
  ];

  for (const table of tables) {
    try {
      await execute(`DELETE FROM "${table}"`);
    } catch {
      // Table might not exist, ignore
    }
  }
} // ---------------------------------------------------------------------------
// Test assertions (used in test files with vitest expect)
// These are typed to work with vitest's expect but don't import it directly
// to avoid coupling. Tests should use vitest's expect directly.
// ---------------------------------------------------------------------------

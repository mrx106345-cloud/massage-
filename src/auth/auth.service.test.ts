import { describe, it, expect, beforeEach } from 'vitest';
import { resetDb, createSchema, selectOne, selectAll } from '../db/index.js';
import {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  type AuthRequest,
  signup,
  login,
  refreshToken,
  requireAuth,
} from '../services/auth.service.js';
import { createGroup } from '../services/groups.service.js';
import type { Request, Response } from 'express';

// Thin request/response factories so we can call the service endpoints without a
// real HTTP server in unit tests.
function makeReq(
  body: Record<string, unknown> = {},
  params: Record<string, string> = {},
  headers: Record<string, string> = {},
) {
  return {
    body,
    params,
    query: {},
    headers: {
      ...headers,
      authorization: headers.authorization ?? undefined,
    },
    socket: { remoteAddress: '127.0.0.1' },
  } as unknown as Request;
}
function makeRes(): any {
  const res: any = {
    statusCode: 200,
    headers: {},
    _json: undefined,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this._json = payload;
      return this;
    },
    setHeader(k: string, v: string) {
      this.headers[k] = v;
    },
  };
  return res;
}

describe('auth JWT helpers', () => {
  it('signs and verifies an access token with the expected claims', () => {
    const token = signAccessToken('user-1', 'alice', 3);
    const payload = verifyAccessToken(token) as {
      sub: string;
      username: string;
      tokenVersion: number;
    };
    expect(payload.sub).toBe('user-1');
    expect(payload.username).toBe('alice');
    expect(payload.tokenVersion).toBe(3);
  });

  it('signs a refresh token with only a sub', () => {
    const token = signRefreshToken('user-1');
    const payload = verifyAccessToken(token) as { sub: string };
    expect(payload.sub).toBe('user-1');
    expect((payload as Record<string, unknown>).username).toBeUndefined();
  });

  it('rejects a tampered token', () => {
    const token = signAccessToken('user-1', 'alice', 0);
    const tampered = token.slice(0, -4) + 'AAAA';
    expect(() => verifyAccessToken(tampered)).toThrow();
  });
});

describe('auth service endpoints', () => {
  beforeEach(async () => {
    await resetDb();
    await createSchema();
  });

  it('signup creates a user and returns a token + user payload', async () => {
    const req = makeReq({
      email: 'alice@example.com',
      password: 'supersecret1',
      username: 'alice',
    });
    const res = makeRes();
    await signup(req, res);
    expect(res.statusCode).toBe(201);
    const body = res._json as {
      token: string;
      refreshToken: string;
      user: { username: string; email: string; password_hash?: unknown };
    };
    expect(body.user.username).toBe('alice');
    expect(body.user.email).toBe('alice@example.com');
    // Secrets must never be serialised into API responses.
    expect(body.user.password_hash).toBeUndefined();
    expect(body.token).toBeTruthy();
    expect(body.refreshToken).toBeTruthy();
    // Stored credential is hashed, not plaintext.
    const stored = await selectOne('user', { username: 'alice' });
    expect(stored).not.toBeNull();
    expect(stored?.password_hash).not.toBe('supersecret1');
    expect(String(stored?.password_hash)).toMatch(/^\$2[aby]\$/);
  });

  it('signup rejects missing fields', async () => {
    const req = makeReq({ email: 'a@b.com' });
    const res = makeRes();
    await signup(req, res);
    expect(res.statusCode).toBe(400);
  });

  it('signup rejects short passwords', async () => {
    const req = makeReq({ email: 'a@b.com', password: 'short', username: 'x' });
    const res = makeRes();
    await signup(req, res);
    expect(res.statusCode).toBe(400);
    expect((res._json as { error: string }).error.toLowerCase()).toContain('password');
  });

  it('signup rejects invalid emails', async () => {
    const req = makeReq({ email: 'not-an-email', password: 'supersecret1', username: 'x' });
    const res = makeRes();
    await signup(req, res);
    expect(res.statusCode).toBe(400);
  });

  it('signup rejects duplicate username or email', async () => {
    await signup(
      makeReq({ email: 'a@b.com', password: 'supersecret1', username: 'alice' }),
      makeRes(),
    );
    const req = makeReq({ email: 'a@b.com', password: 'supersecret1', username: 'bob' });
    const res = makeRes();
    await signup(req, res);
    expect(res.statusCode).toBe(409);

    const req2 = makeReq({ email: 'bob@b.com', password: 'supersecret1', username: 'alice' });
    const res2 = makeRes();
    await signup(req2, res2);
    expect(res2.statusCode).toBe(409);
  });

  it('login returns a token for valid credentials', async () => {
    await signup(
      makeReq({ email: 'a@b.com', password: 'supersecret1', username: 'alice' }),
      makeRes(),
    );
    const req = makeReq({ email: 'a@b.com', password: 'supersecret1' });
    const res = makeRes();
    await login(req, res);
    expect(res.statusCode).toBe(200);
    const body = res._json as { token: string; user: { username: string } };
    expect(body.user.username).toBe('alice');
    expect(body.token).toBeTruthy();
  });

  it('login rejects wrong password', async () => {
    await signup(
      makeReq({ email: 'a@b.com', password: 'supersecret1', username: 'alice' }),
      makeRes(),
    );
    const req = makeReq({ email: 'a@b.com', password: 'wrongpassword' });
    const res = makeRes();
    await login(req, res);
    expect(res.statusCode).toBe(401);
  });

  it('login rejects unknown email', async () => {
    const req = makeReq({ email: 'nobody@example.com', password: 'anything' });
    const res = makeRes();
    await login(req, res);
    expect(res.statusCode).toBe(401);
  });

  it('requireAuth sets userId on the request for a valid bearer token', async () => {
    await signup(
      makeReq({ email: 'a@b.com', password: 'supersecret1', username: 'alice' }),
      makeRes(),
    );
    const stored = await selectOne('user', { username: 'alice' });
    const token = signAccessToken(String(stored?.id), 'alice', 0);
    const req = makeReq({}, {}, { authorization: `Bearer ${token}` });
    const res = makeRes();
    let calledNext = false;
    await requireAuth(req, res, () => {
      calledNext = true;
    });
    expect(calledNext).toBe(true);
    expect((req as AuthRequest).userId).toBe(String(stored?.id));
  });

  it('requireAuth rejects missing bearer token', async () => {
    const req = makeReq();
    const res = makeRes();
    let calledNext = false;
    await requireAuth(req, res, () => {
      calledNext = true;
    });
    expect(calledNext).toBe(false);
    expect(res.statusCode).toBe(401);
  });

  it('refreshToken rotates a session-backed token and rejects the old one', async () => {
    const signupRes = makeRes();
    await signup(
      makeReq({ email: 'a@b.com', password: 'supersecret1', username: 'alice' }),
      signupRes,
    );
    const { refreshToken: refresh } = signupRes._json as { refreshToken: string };

    const res = makeRes();
    await refreshToken(makeReq({ refreshToken: refresh }), res);
    expect(res.statusCode).toBe(200);
    const body = res._json as { token: string; refreshToken: string };
    expect(body.token).toBeTruthy();
    expect(body.refreshToken).toBeTruthy();
    expect(body.refreshToken).not.toBe(refresh);

    // The rotated token can no longer be used.
    const replay = makeRes();
    await refreshToken(makeReq({ refreshToken: refresh }), replay);
    expect(replay.statusCode).toBe(401);
  });

  it('refreshToken rejects missing refreshToken', async () => {
    const req = makeReq({});
    const res = makeRes();
    await refreshToken(req, res);
    expect(res.statusCode).toBe(400);
  });

  it('refreshToken rejects an invalid refresh token', async () => {
    const req = makeReq({ refreshToken: 'not-a-valid-jwt' });
    const res = makeRes();
    await refreshToken(req, res);
    expect(res.statusCode).toBe(401);
  });
});

describe('groups service (integration)', () => {
  beforeEach(async () => {
    await resetDb();
    await createSchema();
  });

  it('createGroup inserts the group and its members', async () => {
    await signup(
      makeReq({ email: 'a@b.com', password: 'supersecret1', username: 'alice' }),
      makeRes(),
    );
    const admin = await selectOne('user', { username: 'alice' });
    const req = makeReq(
      { groupName: 'Sprint', memberIds: [String(admin?.id)], isPrivate: false },
      {},
      {},
    );
    (req as any).userId = String(admin?.id);
    const res = makeRes();
    await createGroup(req as any, res);
    expect(res.statusCode).toBe(201);
    const body = res._json as { id: string; name: string; gmVersion: number };
    expect(body.name).toBe('Sprint');
    expect(body.gmVersion).toBe(1);

    const group = await selectOne('group', { id: body.id });
    expect(group).not.toBeNull();
    const members = await selectAll('group_member', { group_id: body.id });
    expect(members.length).toBeGreaterThanOrEqual(1);
  });

  it('createGroup rejects when the caller is unauthorized', async () => {
    const req = makeReq({ groupName: 'Empty' }, {}, {});
    // No userId set -> unauthorized.
    const res = makeRes();
    await createGroup(req as any, res);
    expect(res.statusCode).toBe(401);
  });

  it('createGroup creates group even with invalid members (admin is auto-added)', async () => {
    await signup(
      makeReq({ email: 'a@b.com', password: 'supersecret1', username: 'alice' }),
      makeRes(),
    );
    const admin = await selectOne('user', { username: 'alice' });
    const req = makeReq({ groupName: 'Empty', memberIds: ['not-a-real-user'] }, {}, {});
    (req as any).userId = String(admin?.id);
    const res = makeRes();
    await createGroup(req, res);
    // Group is created with just the admin (invalid members are skipped)
    expect(res.statusCode).toBe(201);
  });
});

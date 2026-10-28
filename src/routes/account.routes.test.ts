import { randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import { createSchema, insertRow, resetDb, selectOne } from '../db/index.js';
import { clearOutbox, findLastMailTo } from '../services/mailer.service.js';
import { resetCache } from '../services/cache.js';
import { totpCode } from '../services/totp.service.js';

const PASSWORD = 'supersecret1';

interface Tokens {
  token: string;
  refreshToken: string;
  user: { id: string; username: string; email: string; email_verified: boolean };
}

function tokenFromMail(address: string): string {
  const mail = findLastMailTo(address);
  if (!mail) throw new Error(`no mail delivered to ${address}`);
  const match = mail.text.match(/token=([A-Za-z0-9_%.-]+)/);
  if (!match) throw new Error(`no token link in mail: ${mail.text}`);
  return decodeURIComponent(match[1]);
}

async function signup(
  email = 'alice@example.com',
  username = 'alice',
  password = PASSWORD,
): Promise<Tokens> {
  const res = await request(app).post('/api/v1/auth/signup').send({ email, username, password });
  expect(res.status).toBe(201);
  return res.body as Tokens;
}

function login(
  email = 'alice@example.com',
  password = PASSWORD,
  extra: Record<string, unknown> = {},
) {
  return request(app)
    .post('/api/v1/auth/login')
    .send({ email, password, ...extra });
}

beforeEach(async () => {
  resetDb();
  await createSchema();
  clearOutbox();
  resetCache();
});

describe('auth & account API', () => {
  it('signs up, logs in and authorises bearer requests', async () => {
    const created = await signup();
    expect(created.user.email_verified).toBe(false);
    expect(created.user).not.toHaveProperty('password_hash');

    const sessions = await request(app)
      .get('/api/v1/account/sessions')
      .set('authorization', `Bearer ${created.token}`);
    expect(sessions.status).toBe(200);
    expect(Array.isArray(sessions.body.sessions)).toBe(true);
    expect(sessions.body.sessions.length).toBeGreaterThanOrEqual(1);

    const ok = await login();
    expect(ok.status).toBe(200);
    expect(ok.body.token).toBeTruthy();
    expect(ok.body.refreshToken).toBeTruthy();

    const bad = await login(undefined, 'wrong-password');
    expect(bad.status).toBe(401);

    const missing = await request(app).get('/api/v1/account/sessions');
    expect(missing.status).toBe(401);
  });

  it('emails a verification link that verifies the address exactly once', async () => {
    await signup();
    const token = tokenFromMail('alice@example.com');

    const verified = await request(app).post('/api/v1/auth/verify-email').send({ token });
    expect(verified.status).toBe(200);
    expect(verified.body.emailVerified).toBe(true);

    const stored = await selectOne('user', { email: 'alice@example.com' });
    expect(Boolean(stored?.email_verified)).toBe(true);

    // Single-use token.
    const replay = await request(app).post('/api/v1/auth/verify-email').send({ token });
    expect(replay.status).toBe(400);

    // Resending is idempotent for an already verified account.
    const created = await signup('bob@example.com', 'bob');
    const resend = await request(app)
      .post('/api/v1/auth/verify-email/resend')
      .set('authorization', `Bearer ${created.token}`);
    expect(resend.status).toBe(202);
  });

  it('resets a password, revokes old tokens and blocks the old password', async () => {
    const created = await signup();

    const unknown = await request(app)
      .post('/api/v1/auth/forgot-password')
      .send({ email: 'nobody@example.com' });
    expect(unknown.status).toBe(200);
    expect(unknown.body.message).toBeTruthy();
    expect(findLastMailTo('nobody@example.com')).toBeUndefined();

    const requested = await request(app)
      .post('/api/v1/auth/forgot-password')
      .send({ email: 'alice@example.com' });
    expect(requested.status).toBe(200);

    const token = tokenFromMail('alice@example.com');
    const reset = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token, newPassword: 'brand-new-password' });
    expect(reset.status).toBe(200);

    // The old access token is revoked via the token version bump.
    const stale = await request(app)
      .get('/api/v1/account/sessions')
      .set('authorization', `Bearer ${created.token}`);
    expect(stale.status).toBe(401);

    expect((await login()).status).toBe(401);
    expect((await login(undefined, 'brand-new-password')).status).toBe(200);

    // Reset tokens are single use.
    const replay = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token, newPassword: 'another-password' });
    expect(replay.status).toBe(400);
  });

  it('enrols TOTP, requires it at login and accepts a recovery code once', async () => {
    const created = await signup();
    const auth = { authorization: `Bearer ${created.token}` };

    const status = await request(app).get('/api/v1/auth/2fa/status').set(auth);
    expect(status.status).toBe(200);
    expect(status.body.enabled).toBe(false);

    const setup = await request(app).post('/api/v1/auth/2fa/setup').set(auth);
    expect(setup.status).toBe(200);
    const secret = setup.body.secret as string;
    expect(setup.body.otpauthUrl).toContain('otpauth://totp/');

    const badEnable = await request(app)
      .post('/api/v1/auth/2fa/enable')
      .set(auth)
      .send({ code: '000000' });
    expect(badEnable.status).toBe(400);

    const enabled = await request(app)
      .post('/api/v1/auth/2fa/enable')
      .set(auth)
      .send({ code: totpCode(secret) });
    expect(enabled.status).toBe(200);
    expect(enabled.body.backupCodes).toHaveLength(10);

    const noCode = await login();
    expect(noCode.status).toBe(401);
    expect(noCode.body.code).toBe('totp_required');

    const withCode = await login(undefined, PASSWORD, { totpCode: totpCode(secret) });
    expect(withCode.status).toBe(200);

    const backup = enabled.body.backupCodes[0] as string;
    expect((await login(undefined, PASSWORD, { backupCode: backup })).status).toBe(200);
    // Recovery codes are single use.
    expect((await login(undefined, PASSWORD, { backupCode: backup })).status).toBe(401);

    const disabled = await request(app)
      .post('/api/v1/auth/2fa/disable')
      .set(auth)
      .send({ password: PASSWORD });
    expect(disabled.status).toBe(200);
    expect((await login()).status).toBe(200);
  });

  it('lists and revokes individual sessions', async () => {
    const created = await signup();
    await login();
    const auth = { authorization: `Bearer ${created.token}` };

    const listed = await request(app).get('/api/v1/account/sessions').set(auth);
    expect(listed.status).toBe(200);
    const sessions = listed.body.sessions as Array<{ id: string; createdAt: string }>;
    expect(sessions.length).toBeGreaterThanOrEqual(2);

    const revoked = await request(app)
      .delete(`/api/v1/account/sessions/${sessions[0].id}`)
      .set(auth);
    expect(revoked.status).toBe(200);

    const after = await request(app).get('/api/v1/account/sessions').set(auth);
    expect(after.body.sessions.length).toBe(sessions.length - 1);

    const missing = await request(app).delete('/api/v1/account/sessions/does-not-exist').set(auth);
    expect(missing.status).toBe(404);
  });

  it('rotates refresh tokens and rejects replay of the old one', async () => {
    const created = await signup();

    const rotated = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: created.refreshToken });
    expect(rotated.status).toBe(200);
    expect(rotated.body.refreshToken).not.toBe(created.refreshToken);

    const replay = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: created.refreshToken });
    expect(replay.status).toBe(401);

    const usable = await request(app)
      .get('/api/v1/account/sessions')
      .set('authorization', `Bearer ${rotated.body.token}`);
    expect(usable.status).toBe(200);

    // Logout revokes the newest refresh token.
    const logout = await request(app)
      .post('/api/v1/auth/logout')
      .send({ refreshToken: rotated.body.refreshToken });
    expect(logout.status).toBe(204);

    const afterLogout = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: rotated.body.refreshToken });
    expect(afterLogout.status).toBe(401);
  });

  it('logout-all invalidates every access token and session', async () => {
    const created = await signup();
    const auth = { authorization: `Bearer ${created.token}` };

    const res = await request(app).post('/api/v1/auth/logout-all').set(auth);
    expect(res.status).toBe(204);

    const stale = await request(app).get('/api/v1/account/sessions').set(auth);
    expect(stale.status).toBe(401);
    expect(stale.body.code).toBe('token_revoked');
  });

  it('changes the password only with the current one', async () => {
    const created = await signup();
    const auth = { authorization: `Bearer ${created.token}` };

    const wrong = await request(app)
      .post('/api/v1/auth/change-password')
      .set(auth)
      .send({ currentPassword: 'nope', newPassword: 'another-secret' });
    expect(wrong.status).toBe(401);

    const changed = await request(app)
      .post('/api/v1/auth/change-password')
      .set(auth)
      .send({ currentPassword: PASSWORD, newPassword: 'another-secret' });
    expect(changed.status).toBe(200);

    expect((await login()).status).toBe(401);
    expect((await login(undefined, 'another-secret')).status).toBe(200);
  });

  it('exports account data and records an audit trail', async () => {
    const created = await signup();
    await login();
    const auth = { authorization: `Bearer ${created.token}` };

    const audit = await request(app).get('/api/v1/account/audit').set(auth);
    expect(audit.status).toBe(200);
    expect(audit.body.entries.map((e: { action: string }) => e.action)).toEqual(
      expect.arrayContaining(['user.signup', 'user.login']),
    );

    const exported = await request(app).get('/api/v1/account/export').set(auth);
    expect(exported.status).toBe(200);
    expect(exported.headers['content-disposition']).toContain('attachment');
    expect(exported.body.user.email).toBe('alice@example.com');
    expect(exported.body.user).not.toHaveProperty('password_hash');
    expect(Array.isArray(exported.body.sessions)).toBe(true);
  });

  it('deletes an account and frees the email address', async () => {
    const created = await signup();
    const auth = { authorization: `Bearer ${created.token}` };

    const wrong = await request(app).delete('/api/v1/account').set(auth).send({ password: 'nope' });
    expect(wrong.status).toBe(401);

    const deleted = await request(app)
      .delete('/api/v1/account')
      .set(auth)
      .send({ password: PASSWORD });
    expect(deleted.status).toBe(204);

    expect(await selectOne('user', { email: 'alice@example.com' })).toBeNull();
    expect((await login()).status).toBe(401);
    // The address can be reused after deletion.
    await signup('alice@example.com', 'alice2');
  });

  it('serves published X25519 keys and never leaks emails in search', async () => {
    const alice = await signup('alice@example.com', 'alice');
    const bob = await signup('bob@example.com', 'bobby');
    const auth = { authorization: `Bearer ${alice.token}` };

    const missing = await request(app).get(`/api/v1/users/${bob.user.id}/public-key`).set(auth);
    expect(missing.status).toBe(404);

    const x25519 = 'ab'.repeat(32);
    await insertRow('crypto_key', {
      id: randomUUID(),
      owner_id: bob.user.id,
      key_type: 'identity',
      key_id: 'key-1',
      public_key_pem: null,
      private_key_pem: null,
      x25519_public: x25519,
      curve25519_public: null,
      usage: 'identity',
      expires_at: null,
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    const key = await request(app).get(`/api/v1/users/${bob.user.id}/public-key`).set(auth);
    expect(key.status).toBe(200);
    expect(key.body.keyId).toBe('key-1');
    expect(key.body.x25519_public).toBe(x25519);

    const search = await request(app).get('/api/v1/users/search').query({ q: 'bob' }).set(auth);
    expect(search.status).toBe(200);
    expect(search.body.users.length).toBeGreaterThanOrEqual(1);
    for (const user of search.body.users) expect(user).not.toHaveProperty('email');

    // Search is not an unauthenticated directory.
    expect((await request(app).get('/api/v1/users/search').query({ q: 'bob' })).status).toBe(401);
  });

  it('propagates and echoes request ids', async () => {
    const echoed = await request(app).get('/api/health').set('x-request-id', 'test-request-123');
    expect(echoed.status).toBe(200);
    expect(echoed.headers['x-request-id']).toBe('test-request-123');

    const generated = await request(app).get('/api/health');
    expect(generated.headers['x-request-id']).toMatch(/^req_/);
  });

  it('creates groups, lists them and hides them from non-members', async () => {
    const created = await signup();
    const auth = { authorization: `Bearer ${created.token}` };

    const group = await request(app).post('/api/v1/groups').set(auth).send({ groupName: 'Sprint' });
    expect(group.status).toBe(201);

    const list = await request(app).get('/api/v1/groups').set(auth);
    expect(list.status).toBe(200);
    expect(list.body.groups.map((g: { id: string }) => g.id)).toContain(group.body.id);

    const detail = await request(app).get(`/api/v1/groups/${group.body.id}`).set(auth);
    expect(detail.status).toBe(200);
    expect(detail.body.members).toHaveLength(1);
    expect(Number(detail.body.members[0].is_admin)).toBe(1);

    // Non-members must not be able to probe group existence.
    const other = await signup('other@example.com', 'otheruser');
    const hidden = await request(app)
      .get(`/api/v1/groups/${group.body.id}`)
      .set({ authorization: `Bearer ${other.token}` });
    expect(hidden.status).toBe(404);
  });

  it('issues a media upload URL for an allowed type', async () => {
    const created = await signup();
    const auth = { authorization: `Bearer ${created.token}` };

    const presign = await request(app)
      .post('/api/v1/media/presign')
      .set(auth)
      .send({ fileType: 'image/png', fileName: 'cat.png', sizeBytes: 1024 });
    expect(presign.status).toBe(200);
    expect(presign.body.mediaId).toBeTruthy();
    expect(presign.body.uploadUrl).toBeTruthy();

    const media = await request(app).get(`/api/v1/media/${presign.body.mediaId}`).set(auth);
    expect(media.status).toBe(200);
    expect(media.body.originalName).toBe('cat.png');

    const unsupported = await request(app)
      .post('/api/v1/media/presign')
      .set(auth)
      .send({ fileType: 'application/x-msdownload', fileName: 'evil.exe' });
    expect(unsupported.status).toBe(400);
  });

  it('exposes health, metrics, OpenAPI and the docs page', async () => {
    const health = await request(app).get('/api/health');
    expect(health.status).toBe(200);
    expect(health.body.status).toBe('ok');

    const spec = await request(app).get('/api/openapi.json');
    expect(spec.status).toBe(200);
    expect(spec.body.openapi).toBe('3.1.0');
    expect(Object.keys(spec.body.paths)).toContain('/api/v1/auth/login');

    const docs = await request(app).get('/api/docs');
    expect(docs.status).toBe(200);
    expect(docs.headers['content-type']).toContain('text/html');

    const metrics = await request(app).get('/api/metrics');
    expect(metrics.status).toBe(200);
    expect(metrics.body.app.name).toBe('aegis-chat-api');
  });

  it('sends rate-limit headers and rejects unknown routes with JSON', async () => {
    const signupRes = await request(app)
      .post('/api/v1/auth/signup')
      .send({ email: 'headers@example.com', username: 'headers', password: PASSWORD });
    expect(signupRes.status).toBe(201);
    const headerNames = Object.keys(signupRes.headers).map((h) => h.toLowerCase());
    expect(headerNames.some((h) => h.startsWith('ratelimit-'))).toBe(true);

    const missing = await request(app).get('/api/v1/does-not-exist');
    expect(missing.status).toBe(404);
    expect(missing.body.error).toBe('not found');

    const malformed = await request(app)
      .get('/api/v1/account/audit')
      .set('authorization', 'Bearer not-a-jwt');
    expect(malformed.status).toBe(401);
  });
});

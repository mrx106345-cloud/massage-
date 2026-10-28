// Deny-list discipline regression tests.
// A server that refuses to match an identity must stay generic: it may return
// 404/403/409, but it must never echo back any part of the client-supplied
// identity (name, handle, email, fingerprint, etc.) in the rejection body.
// Returning the value leaks which identities exist and aids account auditing.

import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import { resetDb, createSchema } from '../db/index.js';

// A portable random helper that works in Node (crypto.randomBytes) and in
// browser-like runtimes that only expose crypto.getRandomValues().
function probeHex(bytes: number): string {
  if (typeof crypto !== 'undefined' && typeof (crypto as any).randomBytes === 'function') {
    return (crypto as any).randomBytes(bytes).toString('hex');
  }
  const buf = new Uint8Array(bytes);
  globalThis.crypto?.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('deny responses hide identity material', () => {
  const PASSWORD = 'supersecret1';

  beforeEach(async () => {
    resetDb();
    await createSchema();
  });

  it('does not echo a missing-contact handle in the deny body', async () => {
    const probe = `askdfj${probeHex(4)}`;

    const { body: tokenBody } = await request(app)
      .post('/api/v1/auth/signup')
      .send({
        email: `holder-${probeHex(3)}@example.com`,
        username: `holder-${probeHex(3)}`,
        password: PASSWORD,
      });

    const token = (typeof tokenBody === 'object' && tokenBody?.token) ?? tokenBody?.body?.token;

    const res = await request(app)
      .get(`/api/v1/threads?other=${encodeURIComponent(probe)}`)
      .set('authorization', `Bearer ${token}`);

    const payload = JSON.stringify(res.body ?? {});

    expect(payload).not.toContain(probe);
    expect(res.status >= 400 || res.status === 200).toBe(true);
    if (res.status === 200 && Array.isArray(res.body?.threads)) {
      expect(res.body.threads.length).toBe(0);
    }
  });

  it('does not echo an email-like handle in the deny body', async () => {
    const probe = `probe-${probeHex(3)}@example.invalid`;

    const { body: tokenBody } = await request(app)
      .post('/api/v1/auth/signup')
      .send({
        email: `holder-${probeHex(3)}@example.com`,
        username: `holder-${probeHex(3)}`,
        password: PASSWORD,
      });

    const token = (typeof tokenBody === 'object' && tokenBody?.token) ?? tokenBody?.body?.token;

    const res = await request(app)
      .get(`/api/v1/threads?other=${encodeURIComponent(probe)}`)
      .set('authorization', `Bearer ${token}`);

    expect(JSON.stringify(res.body ?? {})).not.toContain(probe);
    expect(res.status >= 400 || res.status === 200).toBe(true);
  });
});

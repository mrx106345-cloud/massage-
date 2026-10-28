import { beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import { createSchema, resetDb } from '../db/index.js';
import { resetCache } from '../services/cache.js';

beforeEach(async () => {
  resetDb();
  await createSchema();
  resetCache();
});

describe('web client hosting', () => {
  it('serves the SPA shell with security headers', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.headers['cache-control']).toBe('no-cache');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toContain("connect-src 'self' ws: wss:");
    expect(res.text).toContain('<title>Aegis Chat');
    expect(res.text).toContain('/js/app.js');
  });

  it('serves the client modules and the vendored crypto library', async () => {
    const css = await request(app).get('/css/app.css');
    expect(css.status).toBe(200);
    expect(css.headers['content-type']).toMatch(/text\/css/);

    const appJs = await request(app).get('/js/app.js');
    expect(appJs.status).toBe(200);
    expect(appJs.headers['content-type']).toMatch(/javascript/);
    expect(appJs.text).toContain('encryptForRecipient');
    expect(appJs.text).toContain('signMessage');
    // A truncated bundle still returns 200, so assert the whole client is there.
    expect(appJs.text.length).toBeGreaterThan(50_000);

    const cryptoJs = await request(app).get('/js/crypto.js');
    expect(cryptoJs.status).toBe(200);
    expect(cryptoJs.text).toContain('aegis-e2ee-v1');

    const nacl = await request(app).get('/vendor/nacl-fast.min.js');
    expect(nacl.status).toBe(200);
    expect(nacl.text).toContain('tweetnacl');
  });

  it('keeps unknown API routes and assets as JSON 404s', async () => {
    const api = await request(app).get('/api/v1/does-not-exist');
    expect(api.status).toBe(404);
    expect(api.headers['content-type']).toMatch(/application\/json/);
    expect(api.body.error).toBe('not found');

    const asset = await request(app).get('/js/missing.js');
    expect(asset.status).toBe(404);
    expect(asset.headers['content-type']).toMatch(/application\/json/);
  });
});

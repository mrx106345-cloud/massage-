/** Micro-benchmarks for the hot paths (crypto envelope, TOTP verification, DB
 * inserts/reads). Run with `npm run bench`.
 *
 * This is a local sanity check, not a load test: it reports per-operation
 * latency percentiles and throughput so regressions are visible without
 * standing up a load-generation stack.
 */

import { seedEnvDefaults, cfg } from './config/index.js';

seedEnvDefaults({
  NODE_ENV: 'development',
  SOCKET_ENABLED: false,
  PORT: 4125,
  HOST: '0.0.0.0',
  APP_ORIGIN: 'http://localhost:4125',
  DB_DRIVER: 'memory',
  DB_PATH: 'data/bench.db',
  DB_LOG: false,
  AUTO_MIGRATE: true,
  EMAIL_FROM: 'bench@bench.test',
  MAIL_WEBHOOK_URL: '',
  MAIL_WEBHOOK_TOKEN: '',
  EMAIL_VERIFICATION_TTL_HOURS: 24,
  PASSWORD_RESET_TTL_MINUTES: 30,
  REQUIRE_EMAIL_VERIFICATION: false,
  TOTP_ISSUER: 'Bench',
  S3_ENDPOINT: '',
  S3_ACCESS_KEY_ID: '',
  S3_SECRET_ACCESS_KEY: '',
  S3_BUCKET: 'bench-media',
  S3_REGION: 'us-east-1',
  S3_OBJECT_URL_EXPIRES_IN: 900,
  E2EE_PREKEY_BUNDLE_COUNT: 100,
  METRICS_TOKEN: '',
  MAINTENANCE_MODE: false,
  LOGIN_MAX_ATTEMPTS: 10,
  LOGIN_LOCKOUT_MINUTES: 15,
  DB_POOL_MAX: 10,
  JWT_ACCESS_EXPIRES_IN: '15m',
  JWT_REFRESH_EXPIRES_IN: '30d',
  RATE_LIMIT_CHAT_PER_MIN: 120,
  SESSION_TTL_DAYS: 30,
  RATE_LIMIT_WINDOW_MS: 60000,
  RATE_LIMIT_MAX: 10000,
  RATE_LIMIT_AUTH_MAX: 10000,
  RATE_LIMIT_SENSITIVE_MAX: 10000,
  CORS_ORIGIN: 'http://localhost:5173',
  TRUST_PROXY: false,
  JWT_SECRET: 'bench-bench-bench-bench-bench-bench-bench-bench',
});

// Confirm the seeded environment is valid before running the benchmark loop.
{
  void cfg;
}

interface Result {
  label: string;
  iterations: number;
  opsPerSecond: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, index)];
}

async function measure(
  label: string,
  iterations: number,
  fn: (index: number) => Promise<unknown> | unknown,
  warmup = Math.min(50, Math.floor(iterations / 10)),
): Promise<Result> {
  for (let i = 0; i < warmup; i += 1) await fn(i);

  const samples: number[] = [];
  const started = performance.now();
  for (let i = 0; i < iterations; i += 1) {
    const opStart = performance.now();
    await fn(i);
    samples.push(performance.now() - opStart);
  }
  const elapsed = performance.now() - started;
  samples.sort((a, b) => a - b);

  return {
    label,
    iterations,
    opsPerSecond: Math.round((iterations / elapsed) * 1000),
    p50Ms: Number(percentile(samples, 50).toFixed(3)),
    p95Ms: Number(percentile(samples, 95).toFixed(3)),
    p99Ms: Number(percentile(samples, 99).toFixed(3)),
  };
}

async function main(): Promise<void> {
  const cryptoService = await import('./services/crypto.service.js');
  const totp = await import('./services/totp.service.js');
  const db = await import('./db/index.js');

  const recipient = cryptoService.generateKeyPackage();
  const sender = cryptoService.generateKeyPackage();
  const chain = {
    senderSessionKeyId: sender.identityKeyId,
    recipientSessionKeyId: recipient.identityKeyId,
  };
  const recipientKey = { keyId: recipient.identityKeyId, publicKeyHex: recipient.publicKeyHex };
  const payload = 'x'.repeat(256);

  const envelope = cryptoService.encryptForRecipient(payload, recipientKey, chain);
  const secret = totp.generateTotpSecret();
  const code = totp.totpCode(secret);

  await db.resetDb();
  await db.createSchema();

  const results: Result[] = [];

  results.push(
    await measure('crypto.encrypt (256B, X25519+HKDF+AES-GCM)', 1000, () =>
      cryptoService.encryptForRecipient(payload, recipientKey, chain),
    ),
  );
  results.push(
    await measure('crypto.decrypt (256B)', 1000, () =>
      cryptoService.decryptWithRecipient(envelope, recipient.privateKeyHex),
    ),
  );
  results.push(
    await measure('crypto.generateKeyPackage (X25519)', 500, () =>
      cryptoService.generateKeyPackage(),
    ),
  );
  results.push(
    await measure('totp.verify (6 digits, ±1 step)', 2000, () => totp.verifyTotp(secret, code)),
  );
  results.push(
    await measure(
      'db.insert user row (SQLite memory)',
      500,
      async (index) => {
        await db.insertRow('user', {
          id: `bench-${index}`,
          username: `bench${index}`,
          email: `bench${index}@example.com`,
          password_hash: 'x',
          token_version: 0,
          is_online: false,
          email_verified: false,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });
      },
      0,
    ),
  );
  results.push(
    await measure('db.selectOne by email', 1000, (index) =>
      db.selectOne('user', { email: `bench${index % 500}@example.com` }),
    ),
  );
  results.push(
    await measure('db.selectAll user search (LIKE)', 200, () =>
      db.selectAll('user', { username: { _like: 'bench1%' } }, 20),
    ),
  );

  console.table(
    results.map((result) => ({
      benchmark: result.label,
      iterations: result.iterations,
      'ops/sec': result.opsPerSecond,
      'p50 ms': result.p50Ms,
      'p95 ms': result.p95Ms,
      'p99 ms': result.p99Ms,
    })),
  );

  await db.shutdown();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

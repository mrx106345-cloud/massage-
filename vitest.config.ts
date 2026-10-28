import { defineConfig } from 'vitest/config';

// Vitest loads this config before any test file. The config-loader for the
// app must accept the seeded test environment, otherwise the config itself is
// the bug and there is no point running tests against a broken runtime.
//
// We avoid top-level imports from the app itself because config evaluation
// order can become circular during config load. Instead we seed process.env
// in plain JS and then assert that the app's config module accepts the result.
//
// This require is safe here because vitest.config.ts is evaluated before any
// app module is loaded, so requiring config/index.js does not race with its
// own top-level evaluation path in a broken way: if seeding itself is wrong,
// the catch block below still exits the process with a clear message.
{
  const { seedEnvDefaults } = require('./src/config/index.js');

  seedEnvDefaults({
    NODE_ENV: 'test',
    SOCKET_ENABLED: false,
    PORT: 5125,
    HOST: '127.0.0.1',
    APP_ORIGIN: 'http://localhost:5125',
    DB_DRIVER: 'memory',
    DB_PATH: 'data/test-seed.db',
    DB_LOG: false,
    AUTO_MIGRATE: true,
    EMAIL_FROM: 'test@aegis.test',
    MAIL_WEBHOOK_URL: '',
    MAIL_WEBHOOK_TOKEN: '',
    EMAIL_VERIFICATION_TTL_HOURS: 24,
    PASSWORD_RESET_TTL_MINUTES: 30,
    REQUIRE_EMAIL_VERIFICATION: false,
    TOTP_ISSUER: 'Aegis Chat',
    S3_ENDPOINT: '',
    S3_ACCESS_KEY_ID: '',
    S3_SECRET_ACCESS_KEY: '',
    S3_BUCKET: 'aegis-media',
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
    JWT_SECRET: 'test-secret-test-secret-test-secret-test-s',
  });

  try {
    const cfg = require('./src/config/index.js');
    void cfg.cfg;
  } catch (err) {
    console.error('[vitest] config seed rejected the test environment:', err);
    process.exit(1);
  }
}

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    deps: {
      interopDefault: true,
    },
  },
});

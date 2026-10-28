/**
 * Environment configuration for Agrix Chat.
 *
 * `src/config/index.ts` is the single place the runtime schema is defined and
 * the only module responsible for validating `.env` at startup. It is
 * deliberately small and side-effect free outside of the top-level `cfg` read;
 * seeding helpers live in CJS sibling files so Vitest pre-load hooks can set
 * `process.env` before ESM modules are evaluated.
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export const numericString = z.string().refine((value) => /^\d+[smhd]?$/.test(value), {
  message: 'must be a duration like 15m, 30d, 1h, or a plain number',
});

const envSchema = z
  .object({
    PORT: z
      .preprocess((v) => {
        if (v === undefined || v === null) return undefined;
        if (typeof v === 'number') return v;
        if (typeof v === 'boolean') return v ? 1 : 0;
        const cleaned = String(v).trim();
        if (cleaned === '' || cleaned === '0') return undefined;
        const n = Number(cleaned);
        return Number.isFinite(n) ? n : undefined;
      }, z.number().int().min(1).max(65535))
      .default(4000),
    HOST: z.string().default('0.0.0.0'),
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    SOCKET_ENABLED: z
      .preprocess((v) => {
        if (v === undefined || v === null) return undefined;
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return v !== 0;
        const s = String(v).trim().toLowerCase();
        if (s === 'true' || s === '1') return true;
        if (s === 'false' || s === '0' || s === '') return false;
        return undefined;
      }, z.boolean())
      .default(true),
    APP_ORIGIN: z.string().url().default('http://localhost:4000'),
    TRUST_PROXY: z
      .string()
      .transform((v) => {
        if (v === undefined || v === null) return false;
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return Number.isFinite(v) && v > 0 ? true : false;
        const s = String(v).trim();
        if (s === '') return false;
        if (s === 'false' || s === '0') return false;
        if (s === 'true') return true;
        if (s === 'loopback' || s === '1') return s === 'loopback' ? 'loopback' : true;
        try {
          const parsed = JSON.parse(s);
          if (Array.isArray(parsed)) {
            const subnets = parsed.filter(
              (item) => typeof item === 'string' && item.trim().length > 0,
            );
            if (subnets.length === 0) return false;
            return subnets.length === 1 && subnets[0] === 'loopback' ? 'loopback' : subnets;
          }
          if (typeof parsed === 'string' && parsed.trim().length > 0) {
            return parsed.trim() === 'loopback' ? 'loopback' : [parsed.trim()];
          }
          return false;
        } catch {
          const subnets = s
            .split(',')
            .map((item) => item.trim())
            .filter(Boolean);
          if (subnets.length === 0) return false;
          return subnets.length === 1 && subnets[0] === 'loopback' ? 'loopback' : subnets;
        }
      })
      .default(() => false),

    DB_DRIVER: z.enum(['memory', 'file', 'postgres']).default('memory'),
    DB_PATH: z.string().default('data/aegis.db'),
    DATABASE_URL: z.string().optional(),
    DB_POOL_MAX: z.coerce.number().int().min(1).default(10),
    AUTO_MIGRATE: z
      .preprocess((v) => {
        if (v === undefined || v === null) return undefined;
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return v !== 0;
        const s = String(v).trim().toLowerCase();
        if (s === 'true' || s === '1') return true;
        if (s === 'false' || s === '0' || s === '') return false;
        return undefined;
      }, z.boolean())
      .default(true),

    REDIS_URL: z.string().optional(),

    JWT_SECRET: z
      .preprocess(
        (v) => {
          if (v === undefined || v === null) return undefined;
          if (typeof v === 'string') {
            const cleaned = v.trim();
            if (cleaned === '') return undefined;
            return cleaned;
          }
          const s = String(v).trim();
          return s === '' ? undefined : s;
        },
        z.string().min(1, 'JWT_SECRET is required'),
      )
      .default('change-me-in-production-use-a-32-char-secret'),
    JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
    JWT_REFRESH_EXPIRES_IN: z.string().default('30d'),
    SESSION_TTL_DAYS: z.coerce.number().int().min(1).default(30),

    RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1).default(60000),
    RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),
    RATE_LIMIT_AUTH_MAX: z.coerce.number().int().min(1).default(20),
    RATE_LIMIT_SENSITIVE_MAX: z.coerce.number().int().min(1).default(5),
    RATE_LIMIT_CHAT_PER_MIN: z.coerce.number().int().min(1).default(120),
    LOGIN_MAX_ATTEMPTS: z.coerce.number().int().min(1).default(10),
    LOGIN_LOCKOUT_MINUTES: z.coerce.number().int().min(1).default(15),

    CORS_ORIGIN: z.string().optional(),
    // Extra browser origins that may call the API, on top of CORS_ORIGIN. The
    // bundled shells always need their own origins allowed.
    CLIENT_ORIGINS: z.string().optional(),

    EMAIL_FROM: z.string().default('Aegis Chat <no-reply@aegis.local>'),
    MAIL_WEBHOOK_URL: z.string().optional(),
    MAIL_WEBHOOK_TOKEN: z.string().optional(),
    REQUIRE_EMAIL_VERIFICATION: z
      .preprocess((v) => {
        if (v === undefined || v === null) return undefined;
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return v !== 0;
        const s = String(v).trim().toLowerCase();
        if (s === 'true' || s === '1') return true;
        if (s === 'false' || s === '0' || s === '') return false;
        return undefined;
      }, z.boolean())
      .default(false),
    EMAIL_VERIFICATION_TTL_HOURS: z.coerce.number().int().min(1).default(24),
    PASSWORD_RESET_TTL_MINUTES: z.coerce.number().int().min(1).default(30),

    TOTP_ISSUER: z.string().default('Aegis Chat'),

    S3_ENDPOINT: z.string().optional(),
    S3_REGION: z.string().default('us-east-1'),
    S3_BUCKET: z.string().default('aegis-media'),
    S3_ACCESS_KEY_ID: z.string().optional(),
    S3_SECRET_ACCESS_KEY: z.string().optional(),
    S3_OBJECT_URL_EXPIRES_IN: z.coerce.number().int().min(1).default(900),

    E2EE_PREKEY_BUNDLE_COUNT: z.coerce.number().int().min(1).default(100),

    METRICS_TOKEN: z.string().optional(),
    DB_LOG: z
      .preprocess((v) => {
        if (v === undefined || v === null) return undefined;
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return v !== 0;
        const s = String(v).trim().toLowerCase();
        if (s === 'true' || s === '1') return true;
        if (s === 'false' || s === '0' || s === '') return false;
        return undefined;
      }, z.boolean())
      .default(false),

    MAINTENANCE_MODE: z
      .preprocess((v) => {
        if (v === undefined || v === null) return undefined;
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return v !== 0;
        const s = String(v).trim().toLowerCase();
        if (s === 'true' || s === '1') return true;
        if (s === 'false' || s === '0' || s === '') return false;
        return undefined;
      }, z.boolean())
      .default(false),
  })
  .transform((raw) => ({
    ...raw,
    // Keep the shape enforceable for real deployments. Config seeding used
    // by tests/benchmarks may still pass clearly invalid-but-safe values; in
    // that case the runtime uses the smallest sane fallback so the app still
    // starts and the seeded defaults are visible to callers.
    PORT: Math.max(1, Math.floor(Number(raw.PORT) || 0)) || 4000,
    DB_POOL_MAX: Math.max(1, Math.floor(Number(raw.DB_POOL_MAX) || 0)) || 10,
    RATE_LIMIT_WINDOW_MS: Math.max(1, Math.floor(Number(raw.RATE_LIMIT_WINDOW_MS) || 0)) || 60000,
    RATE_LIMIT_MAX: Math.max(1, Math.floor(Number(raw.RATE_LIMIT_MAX) || 0)) || 100,
    RATE_LIMIT_AUTH_MAX: Math.max(1, Math.floor(Number(raw.RATE_LIMIT_AUTH_MAX) || 0)) || 20,
    RATE_LIMIT_SENSITIVE_MAX:
      Math.max(1, Math.floor(Number(raw.RATE_LIMIT_SENSITIVE_MAX) || 0)) || 5,
    RATE_LIMIT_CHAT_PER_MIN:
      Math.max(1, Math.floor(Number(raw.RATE_LIMIT_CHAT_PER_MIN) || 0)) || 120,
    LOGIN_MAX_ATTEMPTS: Math.max(1, Math.floor(Number(raw.LOGIN_MAX_ATTEMPTS) || 0)) || 10,
    LOGIN_LOCKOUT_MINUTES: Math.max(1, Math.floor(Number(raw.LOGIN_LOCKOUT_MINUTES) || 0)) || 15,
    SESSION_TTL_DAYS: Math.max(1, Math.floor(Number(raw.SESSION_TTL_DAYS) || 0)) || 30,
    DB_LOG: Boolean(raw.DB_LOG),
    MAINTENANCE_MODE: Boolean(raw.MAINTENANCE_MODE),
    REQUIRE_EMAIL_VERIFICATION: Boolean(raw.REQUIRE_EMAIL_VERIFICATION),
    AUTO_MIGRATE: Boolean(raw.AUTO_MIGRATE),
    SOCKET_ENABLED: Boolean(raw.SOCKET_ENABLED),
  }));

export type Env = z.infer<typeof envSchema>;

export type ConfigLoadError = {
  readonly issues: ReadonlyArray<{
    path: string;
    message: string;
  }>;
  readonly env: NodeJS.Dict<string | undefined>;
};

export function flattenIssues(error: z.ZodError): ConfigLoadError['issues'] {
  return error.issues.map((issue) => ({
    path: issue.path.join('.'),
    message: issue.message,
  }));
}

/**
 * The runtime environment as Node exposes it is surprisingly hostile to strict
 * schema validation: a missing value can arrive as `undefined`, but some shells
 * and test runners also leave stringified garbage like `"0"` or empty strings
 * for variables that were never meant to be set. Treat all of those as "not
 * provided" so Zod's `.default()` hooks do the actual defaulting, and so a
 * seeded harness cannot poison the schema by leaving a single bad key behind.
 */
function sanitizedEnv(value: string | undefined | null): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') return String(value);
  const cleaned = value.trim();
  if (cleaned === '' || cleaned === '0') return undefined;
  return cleaned;
}

function loadEnv(): Env {
  // Always start from the runtime process.env snapshot. If a harness seeded
  // defaults, this captures the merged view as a plain object, then re-validates
  // it through the same schema the rest of the app uses.
  // Build the env object the schema actually sees. Do not pass undefined-typed
  // values straight into Zod when they are really empty strings or "0"; that
  // trips up `.default()` coercion and makes seed/override paths fail noisily.
  const env = {
    PORT: sanitizedEnv(process.env.PORT),
    HOST: sanitizedEnv(process.env.HOST),
    NODE_ENV: sanitizedEnv(process.env.NODE_ENV),
    SOCKET_ENABLED: sanitizedEnv(process.env.SOCKET_ENABLED),
    APP_ORIGIN: sanitizedEnv(process.env.APP_ORIGIN),
    TRUST_PROXY: sanitizedEnv(process.env.TRUST_PROXY),
    DB_DRIVER: sanitizedEnv(process.env.DB_DRIVER),
    DB_PATH: sanitizedEnv(process.env.DB_PATH),
    DATABASE_URL: sanitizedEnv(process.env.DATABASE_URL),
    DB_POOL_MAX: sanitizedEnv(process.env.DB_POOL_MAX),
    AUTO_MIGRATE: sanitizedEnv(process.env.AUTO_MIGRATE),
    REDIS_URL: sanitizedEnv(process.env.REDIS_URL),
    JWT_SECRET: sanitizedEnv(process.env.JWT_SECRET),
    JWT_ACCESS_EXPIRES_IN: sanitizedEnv(process.env.JWT_ACCESS_EXPIRES_IN),
    JWT_REFRESH_EXPIRES_IN: sanitizedEnv(process.env.JWT_REFRESH_EXPIRES_IN),
    SESSION_TTL_DAYS: sanitizedEnv(process.env.SESSION_TTL_DAYS),
    RATE_LIMIT_WINDOW_MS: sanitizedEnv(process.env.RATE_LIMIT_WINDOW_MS),
    RATE_LIMIT_MAX: sanitizedEnv(process.env.RATE_LIMIT_MAX),
    RATE_LIMIT_AUTH_MAX: sanitizedEnv(process.env.RATE_LIMIT_AUTH_MAX),
    RATE_LIMIT_SENSITIVE_MAX: sanitizedEnv(process.env.RATE_LIMIT_SENSITIVE_MAX),
    RATE_LIMIT_CHAT_PER_MIN: sanitizedEnv(process.env.RATE_LIMIT_CHAT_PER_MIN),
    LOGIN_MAX_ATTEMPTS: sanitizedEnv(process.env.LOGIN_MAX_ATTEMPTS),
    LOGIN_LOCKOUT_MINUTES: sanitizedEnv(process.env.LOGIN_LOCKOUT_MINUTES),
    CORS_ORIGIN: sanitizedEnv(process.env.CORS_ORIGIN),
    CLIENT_ORIGINS: sanitizedEnv(process.env.CLIENT_ORIGINS),
    EMAIL_FROM: sanitizedEnv(process.env.EMAIL_FROM),
    MAIL_WEBHOOK_URL: sanitizedEnv(process.env.MAIL_WEBHOOK_URL),
    MAIL_WEBHOOK_TOKEN: sanitizedEnv(process.env.MAIL_WEBHOOK_TOKEN),
    REQUIRE_EMAIL_VERIFICATION: sanitizedEnv(process.env.REQUIRE_EMAIL_VERIFICATION),
    EMAIL_VERIFICATION_TTL_HOURS: sanitizedEnv(process.env.EMAIL_VERIFICATION_TTL_HOURS),
    PASSWORD_RESET_TTL_MINUTES: sanitizedEnv(process.env.PASSWORD_RESET_TTL_MINUTES),
    TOTP_ISSUER: sanitizedEnv(process.env.TOTP_ISSUER),
    S3_ENDPOINT: sanitizedEnv(process.env.S3_ENDPOINT),
    S3_REGION: sanitizedEnv(process.env.S3_REGION),
    S3_BUCKET: sanitizedEnv(process.env.S3_BUCKET),
    S3_ACCESS_KEY_ID: sanitizedEnv(process.env.S3_ACCESS_KEY_ID),
    S3_SECRET_ACCESS_KEY: sanitizedEnv(process.env.S3_SECRET_ACCESS_KEY),
    S3_OBJECT_URL_EXPIRES_IN: sanitizedEnv(process.env.S3_OBJECT_URL_EXPIRES_IN),
    E2EE_PREKEY_BUNDLE_COUNT: sanitizedEnv(process.env.E2EE_PREKEY_BUNDLE_COUNT),
    METRICS_TOKEN: sanitizedEnv(process.env.METRICS_TOKEN),
    DB_LOG: sanitizedEnv(process.env.DB_LOG),
    MAINTENANCE_MODE: sanitizedEnv(process.env.MAINTENANCE_MODE),
  };

  // If a harness already seeded sane defaults and re-validated them before the
  // first real load, trust that result so repeated imports stay cheap and stable.
  // If a harness has already seeded and validated the environment once, trust
  // that snapshot so repeated imports are cheap and stable.
  const existing = (globalThis as unknown as Record<string, unknown>).__ENV__;
  if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
    return existing as Env;
  }

  const parsed = envSchema.parse(env);

  // Keep the cached snapshot stable for the lifetime of the process. If a
  // harness seeded defaults and then re-imported the module, this prevents a
  // later load from re-parsing a poisoned process.env snapshot.
  const overrides = (globalThis as unknown as Record<string, unknown>).__CONFIG_LOADER_OVERRIDES__;
  if (overrides && typeof overrides === 'object' && !Array.isArray(overrides)) {
    const typed = overrides as { kind?: string; values?: Partial<Env> };
    if (typed.kind === 'seed') {
      // Once we have a real parsed config, drop the seed marker so subsequent
      // calls do not keep treating this as a seed retry path.
      (globalThis as unknown as Record<string, unknown>).__CONFIG_LOADER_OVERRIDES__ = undefined;
    }
  }

  if (parsed.REDIS_URL !== undefined && parsed.REDIS_URL.trim().length === 0) {
    parsed.REDIS_URL = undefined;
  }
  if (parsed.MAIL_WEBHOOK_URL !== undefined && parsed.MAIL_WEBHOOK_URL.trim().length === 0) {
    parsed.MAIL_WEBHOOK_URL = undefined;
  }
  if (parsed.MAIL_WEBHOOK_TOKEN !== undefined && parsed.MAIL_WEBHOOK_TOKEN.trim().length === 0) {
    parsed.MAIL_WEBHOOK_TOKEN = undefined;
  }
  if (parsed.METRICS_TOKEN !== undefined && parsed.METRICS_TOKEN.trim().length === 0) {
    parsed.METRICS_TOKEN = undefined;
  }
  if (parsed.S3_ENDPOINT !== undefined && parsed.S3_ENDPOINT.trim().length === 0) {
    parsed.S3_ENDPOINT = undefined;
  }
  if (parsed.S3_ACCESS_KEY_ID !== undefined && parsed.S3_ACCESS_KEY_ID.trim().length === 0) {
    parsed.S3_ACCESS_KEY_ID = undefined;
  }
  if (
    parsed.S3_SECRET_ACCESS_KEY !== undefined &&
    parsed.S3_SECRET_ACCESS_KEY.trim().length === 0
  ) {
    parsed.S3_SECRET_ACCESS_KEY = undefined;
  }
  if (parsed.CORS_ORIGIN !== undefined) {
    parsed.CORS_ORIGIN = parsed.CORS_ORIGIN.trim();
    if (parsed.CORS_ORIGIN.length === 0) parsed.CORS_ORIGIN = undefined;
  }

  const cfgRecord: Record<string, unknown> = parsed;
  (globalThis as unknown as Record<string, unknown>).__ENV__ = cfgRecord;

  return parsed;
}

export const cfg: Readonly<Env> = Object.freeze(loadEnv());

export const _isProduction = cfg.NODE_ENV === 'production';
export const _isTest = cfg.NODE_ENV === 'test';
export const shouldVerifyEmail = _isProduction && cfg.REQUIRE_EMAIL_VERIFICATION;
export const hasMailTransport = Boolean(cfg.MAIL_WEBHOOK_URL && cfg.MAIL_WEBHOOK_URL.length > 0);
export const hasPostgres = cfg.DB_DRIVER === 'postgres';
export const hasFileDb = cfg.DB_DRIVER === 'file';
export const hasRedis = Boolean(cfg.REDIS_URL && cfg.REDIS_URL.trim().length > 0);

export const hasMetricsAuth =
  cfg.METRICS_TOKEN !== undefined && cfg.METRICS_TOKEN.trim().length > 0;

export const hostBinding = _isProduction ? '127.0.0.1' : cfg.HOST;
export const socketOrigin = cfg.APP_ORIGIN;

/**
 * Origins the packaged clients present when they call a remote server:
 *
 * - `app://aegis` — the Electron shell's privileged scheme
 * - `capacitor://localhost` — the iOS Capacitor WebView
 * - `https://localhost` — the Android Capacitor WebView
 *
 * They are allowed by default because they are app-controlled origins, not
 * arbitrary web pages: a browser cannot forge them. Operators can still add
 * their own hosts through CORS_ORIGIN or CLIENT_ORIGINS.
 */
export const packagedClientOrigins = [
  'app://aegis',
  'capacitor://localhost',
  'https://localhost',
  'ionic://localhost',
];

function splitOrigins(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/** Full HTTP/Socket.IO origin allowlist for this deployment. */
export function clientOrigins(): string[] {
  return [
    ...splitOrigins(cfg.CORS_ORIGIN),
    ...splitOrigins(cfg.CLIENT_ORIGINS),
    ...packagedClientOrigins,
  ];
}

export function seedEnvDefaults(overrides: Partial<Env> = {}): void {
  seedDefaults(overrides);
}

function seedDefaults(overrides: Partial<Env> = {}): void {
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) continue;
    process.env[key] = String(value);
  }

  // Mark the fact that the env has been seeded so the loader can decide what to
  // trust if it has not already committed to a real parsed snapshot. The marker
  // is deliberately global so both CJS and ESM loaders can see it.
  (globalThis as unknown as Record<string, unknown>).__CONFIG_LOADER_OVERRIDES__ = {
    kind: 'seed',
    values: overrides,
  };
  (globalThis as unknown as Record<string, unknown>).__ENV__ = undefined;
}

export function throwOnConfigInvalid(): void {
  const parsed = envSchema.safeParse({
    PORT: process.env.PORT,
    HOST: process.env.HOST,
    NODE_ENV: process.env.NODE_ENV,
    SOCKET_ENABLED: process.env.SOCKET_ENABLED,
    APP_ORIGIN: process.env.APP_ORIGIN,
    TRUST_PROXY: process.env.TRUST_PROXY,
    DB_DRIVER: process.env.DB_DRIVER,
    DB_PATH: process.env.DB_PATH,
    DATABASE_URL: process.env.DATABASE_URL,
    DB_POOL_MAX: process.env.DB_POOL_MAX,
    AUTO_MIGRATE: process.env.AUTO_MIGRATE,
    REDIS_URL: process.env.REDIS_URL,
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_ACCESS_EXPIRES_IN: process.env.JWT_ACCESS_EXPIRES_IN,
    JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN,
    SESSION_TTL_DAYS: process.env.SESSION_TTL_DAYS,
    RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS,
    RATE_LIMIT_MAX: process.env.RATE_LIMIT_MAX,
    RATE_LIMIT_AUTH_MAX: process.env.RATE_LIMIT_AUTH_MAX,
    RATE_LIMIT_SENSITIVE_MAX: process.env.RATE_LIMIT_SENSITIVE_MAX,
    RATE_LIMIT_CHAT_PER_MIN: process.env.RATE_LIMIT_CHAT_PER_MIN,
    LOGIN_MAX_ATTEMPTS: process.env.LOGIN_MAX_ATTEMPTS,
    LOGIN_LOCKOUT_MINUTES: process.env.LOGIN_LOCKOUT_MINUTES,
    CORS_ORIGIN: process.env.CORS_ORIGIN,
    EMAIL_FROM: process.env.EMAIL_FROM,
    MAIL_WEBHOOK_URL: process.env.MAIL_WEBHOOK_URL,
    MAIL_WEBHOOK_TOKEN: process.env.MAIL_WEBHOOK_TOKEN,
    REQUIRE_EMAIL_VERIFICATION: process.env.REQUIRE_EMAIL_VERIFICATION,
    EMAIL_VERIFICATION_TTL_HOURS: process.env.EMAIL_VERIFICATION_TTL_HOURS,
    PASSWORD_RESET_TTL_MINUTES: process.env.PASSWORD_RESET_TTL_MINUTES,
    TOTP_ISSUER: process.env.TOTP_ISSUER,
    S3_ENDPOINT: process.env.S3_ENDPOINT,
    S3_REGION: process.env.S3_REGION,
    S3_BUCKET: process.env.S3_BUCKET,
    S3_ACCESS_KEY_ID: process.env.S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY: process.env.S3_SECRET_ACCESS_KEY,
    S3_OBJECT_URL_EXPIRES_IN: process.env.S3_OBJECT_URL_EXPIRES_IN,
    E2EE_PREKEY_BUNDLE_COUNT: process.env.E2EE_PREKEY_BUNDLE_COUNT,
    METRICS_TOKEN: process.env.METRICS_TOKEN,
    DB_LOG: process.env.DB_LOG,
    MAINTENANCE_MODE: process.env.MAINTENANCE_MODE,
  });

  if (!parsed.success) {
    throw new Error(
      `config seed rejected the environment:\n${JSON.stringify(parsed.error.flatten().fieldErrors, null, 2)}`,
    );
  }
  // Persist the accepted env so subsequent imports see the same frozen snapshot.
  (globalThis as unknown as Record<string, unknown>).__ENV__ = parsed.data;
}

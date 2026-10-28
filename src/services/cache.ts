/**
 * Cache / counter store.
 *
 * Uses Redis when `REDIS_URL` is configured (login lockout counters, cached
 * sessions) and transparently falls back to an in-process map otherwise, so the
 * app runs without infrastructure while behaving identically in tests.
 */

interface CacheEntry {
  value: string;
  expiresAt: number | null;
}

const memory = new Map<string, CacheEntry>();

interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, ttl?: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  incr(key: string): Promise<number>;
  expire(key: string, ttl: number): Promise<unknown>;
  quit(): Promise<unknown>;
}

let redisPromise: Promise<RedisLike | null> | null = null;
let redisDisabled = false;

async function getRedis(): Promise<RedisLike | null> {
  const url = process.env.REDIS_URL;
  if (!url || redisDisabled) return null;
  if (!redisPromise) {
    redisPromise = (async () => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const mod: any = await import('ioredis');
        const RedisCtor = mod.default ?? mod.Redis;
        const client = new RedisCtor(url, {
          lazyConnect: true,
          maxRetriesPerRequest: 1,
          enableOfflineQueue: false,
          connectTimeout: 1000,
        }) as RedisLike & { connect(): Promise<void>; on(event: string, cb: () => void): void };
        // Never let a Redis outage crash the API.
        client.on('error', () => undefined);
        await client.connect();
        return client;
      } catch {
        redisDisabled = true;
        return null;
      }
    })();
  }
  const client = await redisPromise;
  if (!client) return null;
  return client;
}

function memoryGet(key: string): string | null {
  const entry = memory.get(key);
  if (!entry) return null;
  if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
    memory.delete(key);
    return null;
  }
  return entry.value;
}

function memorySet(key: string, value: string, ttlSeconds?: number): void {
  memory.set(key, {
    value,
    expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null,
  });
}

export const cache = {
  async get(key: string): Promise<string | null> {
    const redis = await getRedis();
    if (redis) {
      try {
        return await redis.get(key);
      } catch {
        // fall through to memory
      }
    }
    return memoryGet(key);
  },

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    const redis = await getRedis();
    if (redis) {
      try {
        if (ttlSeconds) await redis.set(key, value, 'EX', ttlSeconds);
        else await redis.set(key, value);
        return;
      } catch {
        // fall through to memory
      }
    }
    memorySet(key, value, ttlSeconds);
  },

  async del(key: string): Promise<void> {
    const redis = await getRedis();
    if (redis) {
      try {
        await redis.del(key);
        return;
      } catch {
        // fall through to memory
      }
    }
    memory.delete(key);
  },

  /** Atomically increment a counter and (re)apply its TTL. */
  async incr(key: string, ttlSeconds: number): Promise<number> {
    const redis = await getRedis();
    if (redis) {
      try {
        const value = await redis.incr(key);
        if (value === 1) await redis.expire(key, ttlSeconds);
        return value;
      } catch {
        // fall through to memory
      }
    }
    const current = Number(memoryGet(key) ?? 0) + 1;
    memorySet(key, String(current), ttlSeconds);
    return current;
  },

  /** Seconds remaining on a key, best effort. */
  async ttl(key: string): Promise<number> {
    const redis = await getRedis();
    if (redis) {
      try {
        const client = redis as RedisLike & { ttl(key: string): Promise<number> };
        return await client.ttl(key);
      } catch {
        // fall through to memory
      }
    }
    const entry = memory.get(key);
    if (!entry || entry.expiresAt === null) return -1;
    return Math.max(0, Math.round((entry.expiresAt - Date.now()) / 1000));
  },
};

/** Clear local state; used by tests that share a process. */
export function resetCache(): void {
  memory.clear();
  redisDisabled = true;
  redisPromise = null;
}

export async function closeCache(): Promise<void> {
  const redis = redisPromise ? await redisPromise.catch(() => null) : null;
  if (redis) await redis.quit().catch(() => undefined);
  redisPromise = null;
  memory.clear();
}

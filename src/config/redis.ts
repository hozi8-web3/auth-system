import Redis from 'ioredis';
import config from './index.js';

// ============================================
// REDIS CLIENT
// ============================================

let redis: Redis | null = null;

export function getRedisClient(): Redis {
    if (!redis) {
        const options: Record<string, unknown> = {
            maxRetriesPerRequest: 3,
            lazyConnect: true,
        };

        // Only add password if set
        if (config.redisPassword) {
            options.password = config.redisPassword;
        }

        redis = new Redis(config.redisUrl, options);

        redis.on('connect', () => {
            console.log('✅ Redis connected successfully');
        });

        redis.on('error', (err) => {
            console.error('❌ Redis connection error:', err.message);
        });

        redis.on('close', () => {
            console.log('📤 Redis connection closed');
        });
    }

    return redis;
}

export async function connectRedis(): Promise<void> {
    const client = getRedisClient();
    // Only connect if not already connected
    if (client.status === 'wait') {
        await client.connect();
    }
}

export async function disconnectRedis(): Promise<void> {
    if (redis && redis.status === 'ready') {
        await redis.quit();
        redis = null;
    }
}

// ============================================
// REDIS HELPERS
// ============================================

/**
 * Store a value with expiration
 */
export async function setWithExpiry(
    key: string,
    value: string,
    expirySeconds: number
): Promise<void> {
    const client = getRedisClient();
    await client.setex(key, expirySeconds, value);
}

/**
 * Get a value
 */
export async function getValue(key: string): Promise<string | null> {
    const client = getRedisClient();
    return client.get(key);
}

/**
 * Delete a key
 */
export async function deleteKey(key: string): Promise<void> {
    const client = getRedisClient();
    await client.del(key);
}

/**
 * Delete keys by pattern
 */
export async function deleteByPattern(pattern: string): Promise<void> {
    const client = getRedisClient();
    const keys = await client.keys(pattern);
    if (keys.length > 0) {
        await client.del(...keys);
    }
}

/**
 * Increment a counter with expiry (for rate limiting)
 */
export async function incrementWithExpiry(
    key: string,
    expirySeconds: number
): Promise<number> {
    const client = getRedisClient();
    const pipeline = client.pipeline();
    pipeline.incr(key);
    pipeline.expire(key, expirySeconds);
    const results = await pipeline.exec();
    return results?.[0]?.[1] as number || 0;
}

export default getRedisClient;

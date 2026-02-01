import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { getRedisClient } from '../config/redis.js';
import config from '../config/index.js';

// ============================================
// RATE LIMITERS
// ============================================

/**
 * Create Redis-backed rate limiter
 */
function createRateLimiter(options: {
    windowMs: number;
    max: number;
    message?: string;
    keyPrefix?: string;
    skipFailedRequests?: boolean;
}) {
    return rateLimit({
        windowMs: options.windowMs,
        max: options.max,
        standardHeaders: true,
        legacyHeaders: false,
        skipFailedRequests: options.skipFailedRequests ?? false,
        message: {
            success: false,
            error: options.message || 'Too many requests, please try again later',
            code: 'RATE_LIMIT_EXCEEDED',
        },
        store: new RedisStore({
            sendCommand: (...args: string[]) => getRedisClient().call(...args),
            prefix: options.keyPrefix || 'rl:',
        }),
        keyGenerator: (req) => {
            // Use IP + endpoint for rate limiting
            const ip =
                req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ||
                req.ip ||
                'unknown';
            return `${ip}:${req.path}`;
        },
    });
}

// ============================================
// PRE-CONFIGURED LIMITERS
// ============================================

/**
 * General API rate limiter
 */
export const generalLimiter = createRateLimiter({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    keyPrefix: 'rl:general:',
});

/**
 * Strict limiter for authentication endpoints
 */
export const authLimiter = createRateLimiter({
    windowMs: config.rateLimit.authWindowMs,
    max: config.rateLimit.authMax,
    message: 'Too many authentication attempts. Please try again later.',
    keyPrefix: 'rl:auth:',
});

/**
 * Very strict limiter for sensitive operations
 */
export const strictLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    message: 'Too many attempts. Please try again in an hour.',
    keyPrefix: 'rl:strict:',
});

/**
 * Password reset limiter (per email)
 */
export const passwordResetLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3,
    message: 'Too many password reset requests. Please try again later.',
    keyPrefix: 'rl:pwreset:',
});

/**
 * Registration limiter (per IP)
 */
export const registerLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    message: 'Too many registration attempts. Please try again later.',
    keyPrefix: 'rl:register:',
});

export default {
    generalLimiter,
    authLimiter,
    strictLimiter,
    passwordResetLimiter,
    registerLimiter,
};

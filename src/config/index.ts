import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';

// Load environment variables
dotenv.config();

// ============================================
// ENVIRONMENT CONFIGURATION
// ============================================

function getEnvVar(key: string, defaultValue?: string): string {
    const value = process.env[key];
    if (!value && defaultValue === undefined) {
        throw new Error(`Missing required environment variable: ${key}`);
    }
    return value || defaultValue!;
}

function getEnvNumber(key: string, defaultValue?: number): number {
    const value = process.env[key];
    if (!value && defaultValue === undefined) {
        throw new Error(`Missing required environment variable: ${key}`);
    }
    return value ? parseInt(value, 10) : defaultValue!;
}

function getEnvBoolean(key: string, defaultValue: boolean): boolean {
    const value = process.env[key];
    if (!value) return defaultValue;
    return value.toLowerCase() === 'true';
}

// ============================================
// CONFIGURATION OBJECT
// ============================================

export const config = {
    // Server
    env: getEnvVar('NODE_ENV', 'development'),
    port: getEnvNumber('PORT', 3000),
    apiVersion: getEnvVar('API_VERSION', 'v1'),
    apiBaseUrl: getEnvVar('API_BASE_URL', 'http://localhost:3000'),
    frontendUrl: getEnvVar('FRONTEND_URL', 'http://localhost:5173'),

    // Database
    databaseUrl: getEnvVar('DATABASE_URL'),

    // Redis
    redisUrl: getEnvVar('REDIS_URL', 'redis://localhost:6379'),
    redisPassword: process.env.REDIS_PASSWORD || undefined,

    // JWT
    jwt: {
        accessTokenExpiry: getEnvVar('JWT_ACCESS_TOKEN_EXPIRY', '15m'),
        refreshTokenExpiry: getEnvVar('JWT_REFRESH_TOKEN_EXPIRY', '7d'),
        issuer: getEnvVar('JWT_ISSUER', 'auth.localhost'),
        audience: getEnvVar('JWT_AUDIENCE', 'api.localhost'),
        privateKeyPath: getEnvVar('JWT_PRIVATE_KEY_PATH', './keys/private.pem'),
        publicKeyPath: getEnvVar('JWT_PUBLIC_KEY_PATH', './keys/public.pem'),
    },

    // Argon2 Password Hashing
    argon2: {
        memoryCost: getEnvNumber('ARGON2_MEMORY_COST', 65536),
        timeCost: getEnvNumber('ARGON2_TIME_COST', 3),
        parallelism: getEnvNumber('ARGON2_PARALLELISM', 4),
    },

    // Rate Limiting
    rateLimit: {
        max: getEnvNumber('RATE_LIMIT_MAX', 100),
        windowMs: getEnvNumber('RATE_LIMIT_WINDOW_MS', 900000),
        authMax: getEnvNumber('AUTH_RATE_LIMIT_MAX', 10),
        authWindowMs: getEnvNumber('AUTH_RATE_LIMIT_WINDOW_MS', 900000),
    },

    // Account Security
    security: {
        maxLoginAttempts: getEnvNumber('MAX_LOGIN_ATTEMPTS', 5),
        lockoutDurationMinutes: getEnvNumber('LOCKOUT_DURATION_MINUTES', 15),
    },

    // Email
    email: {
        host: getEnvVar('SMTP_HOST', 'smtp.gmail.com'),
        port: getEnvNumber('SMTP_PORT', 587),
        secure: getEnvBoolean('SMTP_SECURE', false),
        user: process.env.SMTP_USER || '',
        password: process.env.SMTP_PASSWORD || '',
        fromName: getEnvVar('SMTP_FROM_NAME', 'Enterprise Auth'),
        fromEmail: getEnvVar('SMTP_FROM_EMAIL', 'noreply@localhost'),
        verificationExpiryHours: getEnvNumber('EMAIL_VERIFICATION_EXPIRY_HOURS', 24),
        passwordResetExpiryHours: getEnvNumber('PASSWORD_RESET_EXPIRY_HOURS', 1),
    },

    // Two-Factor Authentication
    twoFactor: {
        issuer: getEnvVar('TWO_FACTOR_ISSUER', 'EnterpriseAuth'),
        backupCodesCount: getEnvNumber('TWO_FACTOR_BACKUP_CODES_COUNT', 10),
    },

    // CORS
    cors: {
        origins: getEnvVar('CORS_ORIGINS', 'http://localhost:5173,http://localhost:3000')
            .split(',')
            .map((origin) => origin.trim()),
    },

    // Cookies
    cookie: {
        domain: process.env.COOKIE_DOMAIN || undefined,
        secure: getEnvBoolean('COOKIE_SECURE', false),
        sameSite: getEnvVar('COOKIE_SAME_SITE', 'lax') as 'lax' | 'strict' | 'none',
    },

    // Logging
    log: {
        level: getEnvVar('LOG_LEVEL', 'debug'),
        format: getEnvVar('LOG_FORMAT', 'dev'),
    },
} as const;

// ============================================
// KEY LOADING
// ============================================

let privateKey: string | null = null;
let publicKey: string | null = null;

export function getPrivateKey(): string {
    if (!privateKey) {
        const keyPath = path.resolve(config.jwt.privateKeyPath);
        if (!fs.existsSync(keyPath)) {
            throw new Error(`Private key not found at ${keyPath}. Run: npm run generate:keys`);
        }
        privateKey = fs.readFileSync(keyPath, 'utf8');
    }
    return privateKey;
}

export function getPublicKey(): string {
    if (!publicKey) {
        const keyPath = path.resolve(config.jwt.publicKeyPath);
        if (!fs.existsSync(keyPath)) {
            throw new Error(`Public key not found at ${keyPath}. Run: npm run generate:keys`);
        }
        publicKey = fs.readFileSync(keyPath, 'utf8');
    }
    return publicKey;
}

// ============================================
// VALIDATION
// ============================================

export function validateConfig(): void {
    const errors: string[] = [];

    // Check required environment variables
    if (!process.env.DATABASE_URL) {
        errors.push('DATABASE_URL is required');
    }

    // Check JWT keys exist
    if (!fs.existsSync(path.resolve(config.jwt.privateKeyPath))) {
        errors.push(`JWT private key not found. Run: npm run generate:keys`);
    }

    if (!fs.existsSync(path.resolve(config.jwt.publicKeyPath))) {
        errors.push(`JWT public key not found. Run: npm run generate:keys`);
    }

    if (errors.length > 0) {
        console.error('❌ Configuration errors:');
        errors.forEach((err) => console.error(`   - ${err}`));
        process.exit(1);
    }
}

export default config;

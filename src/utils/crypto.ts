import crypto from 'crypto';

// ============================================
// SECURE RANDOM GENERATION
// ============================================

/**
 * Generate a cryptographically secure random token
 */
export function generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate a URL-safe Base64 token
 */
export function generateUrlSafeToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('base64url');
}

/**
 * Generate a numeric OTP code
 */
export function generateNumericOtp(length: number = 6): string {
    const max = Math.pow(10, length);
    const randomNum = crypto.randomInt(0, max);
    return randomNum.toString().padStart(length, '0');
}

// ============================================
// HASHING
// ============================================

/**
 * Create SHA-256 hash
 */
export function sha256(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Create HMAC-SHA256
 */
export function hmacSha256(data: string, secret: string): string {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

// ============================================
// ENCRYPTION (AES-256-GCM)
// ============================================

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypt data using AES-256-GCM
 */
export function encrypt(plaintext: string, key: string): string {
    const keyBuffer = crypto.scryptSync(key, 'salt', 32);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    // Format: iv:authTag:encrypted
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decrypt(ciphertext: string, key: string): string {
    const [ivHex, authTagHex, encrypted] = ciphertext.split(':');

    if (!ivHex || !authTagHex || !encrypted) {
        throw new Error('Invalid ciphertext format');
    }

    const keyBuffer = crypto.scryptSync(key, 'salt', 32);
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

// ============================================
// TIMING-SAFE COMPARISON
// ============================================

/**
 * Constant-time string comparison to prevent timing attacks
 */
export function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) {
        return false;
    }

    const bufferA = Buffer.from(a);
    const bufferB = Buffer.from(b);

    return crypto.timingSafeEqual(bufferA, bufferB);
}

import argon2 from 'argon2';
import config from '../config/index.js';

// ============================================
// ARGON2ID PASSWORD HASHING
// ============================================
// Using Argon2id - the recommended algorithm by OWASP
// Provides resistance against both GPU and side-channel attacks

const ARGON2_OPTIONS: argon2.Options = {
    type: argon2.argon2id,
    memoryCost: config.argon2.memoryCost, // 64 MB default
    timeCost: config.argon2.timeCost,     // 3 iterations
    parallelism: config.argon2.parallelism, // 4 threads
    hashLength: 32,                        // 256-bit hash
};

/**
 * Hash a password using Argon2id
 */
export async function hashPassword(password: string): Promise<string> {
    return argon2.hash(password, ARGON2_OPTIONS);
}

/**
 * Verify a password against a hash
 */
export async function verifyPassword(
    password: string,
    hash: string
): Promise<boolean> {
    try {
        return await argon2.verify(hash, password);
    } catch {
        return false;
    }
}

/**
 * Check if a hash needs to be rehashed (parameters changed)
 */
export async function needsRehash(hash: string): Promise<boolean> {
    return argon2.needsRehash(hash, ARGON2_OPTIONS);
}

// ============================================
// PASSWORD VALIDATION
// ============================================

export interface PasswordValidationResult {
    isValid: boolean;
    errors: string[];
}

/**
 * Validate password strength
 * Requirements:
 * - Minimum 12 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 */
export function validatePasswordStrength(password: string): PasswordValidationResult {
    const errors: string[] = [];

    if (password.length < 12) {
        errors.push('Password must be at least 12 characters long');
    }

    if (password.length > 128) {
        errors.push('Password must not exceed 128 characters');
    }

    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number');
    }

    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }

    // Check for common patterns
    if (/^(.)\1+$/.test(password)) {
        errors.push('Password cannot be all the same character');
    }

    if (/^(012|123|234|345|456|567|678|789|890)+$/.test(password)) {
        errors.push('Password cannot be a sequential number pattern');
    }

    return {
        isValid: errors.length === 0,
        errors,
    };
}

import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import config, { getPrivateKey, getPublicKey } from '../config/index.js';
import { sha256 } from './crypto.js';
import prisma from '../config/database.js';

// ============================================
// TOKEN TYPES
// ============================================

export interface AccessTokenPayload {
    sub: string;        // User ID
    email: string;
    type: 'access';
    jti: string;        // JWT ID (for revocation)
}

export interface RefreshTokenPayload {
    sub: string;        // User ID
    type: 'refresh';
    jti: string;        // JWT ID
    sessionId: string;  // Session ID for tracking
}

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
    accessTokenExpiry: Date;
    refreshTokenExpiry: Date;
}

// ============================================
// TOKEN GENERATION
// ============================================

/**
 * Generate an access token
 */
export function generateAccessToken(userId: string, email: string): string {
    const payload: AccessTokenPayload = {
        sub: userId,
        email,
        type: 'access',
        jti: uuidv4(),
    };

    const options: SignOptions = {
        algorithm: 'RS256',
        expiresIn: config.jwt.accessTokenExpiry,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
    };

    return jwt.sign(payload, getPrivateKey(), options);
}

/**
 * Generate a refresh token
 */
export function generateRefreshToken(userId: string, sessionId: string): string {
    const payload: RefreshTokenPayload = {
        sub: userId,
        type: 'refresh',
        jti: uuidv4(),
        sessionId,
    };

    const options: SignOptions = {
        algorithm: 'RS256',
        expiresIn: config.jwt.refreshTokenExpiry,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
    };

    return jwt.sign(payload, getPrivateKey(), options);
}

/**
 * Generate a complete token pair with a new session
 */
export async function generateTokenPair(
    userId: string,
    email: string,
    userAgent?: string,
    ipAddress?: string
): Promise<TokenPair> {
    // Calculate expiry times
    const now = new Date();
    const accessTokenExpiry = new Date(now.getTime() + parseExpiry(config.jwt.accessTokenExpiry));
    const refreshTokenExpiry = new Date(now.getTime() + parseExpiry(config.jwt.refreshTokenExpiry));

    // Generate tokens
    const sessionId = uuidv4();
    const refreshToken = generateRefreshToken(userId, sessionId);
    const accessToken = generateAccessToken(userId, email);

    // Store session in database
    await prisma.session.create({
        data: {
            id: sessionId,
            userId,
            refreshTokenHash: sha256(refreshToken),
            userAgent,
            ipAddress,
            expiresAt: refreshTokenExpiry,
        },
    });

    return {
        accessToken,
        refreshToken,
        accessTokenExpiry,
        refreshTokenExpiry,
    };
}

// ============================================
// TOKEN VERIFICATION
// ============================================

/**
 * Verify an access token
 */
export function verifyAccessToken(token: string): AccessTokenPayload {
    const options: VerifyOptions = {
        algorithms: ['RS256'],
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
    };

    const payload = jwt.verify(token, getPublicKey(), options) as AccessTokenPayload;

    if (payload.type !== 'access') {
        throw new Error('Invalid token type');
    }

    return payload;
}

/**
 * Verify a refresh token
 */
export function verifyRefreshToken(token: string): RefreshTokenPayload {
    const options: VerifyOptions = {
        algorithms: ['RS256'],
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
    };

    const payload = jwt.verify(token, getPublicKey(), options) as RefreshTokenPayload;

    if (payload.type !== 'refresh') {
        throw new Error('Invalid token type');
    }

    return payload;
}

/**
 * Validate refresh token and session
 */
export async function validateRefreshToken(token: string): Promise<{
    payload: RefreshTokenPayload;
    session: Awaited<ReturnType<typeof prisma.session.findUnique>>;
}> {
    const payload = verifyRefreshToken(token);
    const tokenHash = sha256(token);

    // Find and validate session
    const session = await prisma.session.findUnique({
        where: { id: payload.sessionId },
    });

    if (!session) {
        throw new Error('Session not found');
    }

    if (!session.isValid) {
        throw new Error('Session has been revoked');
    }

    if (session.refreshTokenHash !== tokenHash) {
        // Token reuse detected - revoke all sessions for security
        await prisma.session.updateMany({
            where: { userId: payload.sub },
            data: { isValid: false },
        });
        throw new Error('Token reuse detected - all sessions revoked');
    }

    if (session.expiresAt < new Date()) {
        throw new Error('Session expired');
    }

    return { payload, session };
}

// ============================================
// TOKEN ROTATION
// ============================================

/**
 * Rotate refresh token (issue new token, invalidate old)
 */
export async function rotateRefreshToken(
    oldToken: string,
    userAgent?: string,
    ipAddress?: string
): Promise<TokenPair> {
    const { payload, session } = await validateRefreshToken(oldToken);

    // Get user for email
    const user = await prisma.user.findUnique({
        where: { id: payload.sub },
        select: { email: true },
    });

    if (!user) {
        throw new Error('User not found');
    }

    // Generate new tokens
    const now = new Date();
    const accessTokenExpiry = new Date(now.getTime() + parseExpiry(config.jwt.accessTokenExpiry));
    const refreshTokenExpiry = new Date(now.getTime() + parseExpiry(config.jwt.refreshTokenExpiry));

    const newRefreshToken = generateRefreshToken(payload.sub, session!.id);
    const accessToken = generateAccessToken(payload.sub, user.email);

    // Update session with new refresh token hash
    await prisma.session.update({
        where: { id: session!.id },
        data: {
            refreshTokenHash: sha256(newRefreshToken),
            lastUsedAt: now,
            userAgent,
            ipAddress,
            expiresAt: refreshTokenExpiry,
        },
    });

    return {
        accessToken,
        refreshToken: newRefreshToken,
        accessTokenExpiry,
        refreshTokenExpiry,
    };
}

// ============================================
// SESSION MANAGEMENT
// ============================================

/**
 * Revoke a specific session
 */
export async function revokeSession(sessionId: string): Promise<void> {
    await prisma.session.update({
        where: { id: sessionId },
        data: { isValid: false },
    });
}

/**
 * Revoke all sessions for a user
 */
export async function revokeAllSessions(userId: string): Promise<void> {
    await prisma.session.updateMany({
        where: { userId },
        data: { isValid: false },
    });
}

/**
 * Clean up expired sessions
 */
export async function cleanupExpiredSessions(): Promise<number> {
    const result = await prisma.session.deleteMany({
        where: {
            OR: [
                { expiresAt: { lt: new Date() } },
                { isValid: false },
            ],
        },
    });
    return result.count;
}

// ============================================
// HELPERS
// ============================================

/**
 * Parse expiry string to milliseconds
 */
function parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) {
        throw new Error(`Invalid expiry format: ${expiry}`);
    }

    const value = parseInt(match[1]!, 10);
    const unit = match[2];

    switch (unit) {
        case 's':
            return value * 1000;
        case 'm':
            return value * 60 * 1000;
        case 'h':
            return value * 60 * 60 * 1000;
        case 'd':
            return value * 24 * 60 * 60 * 1000;
        default:
            throw new Error(`Unknown time unit: ${unit}`);
    }
}

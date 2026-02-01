import { Request, Response, NextFunction } from 'express';
import prisma from '../config/database.js';
import { sha256 } from '../utils/crypto.js';
import { createAuditLog, AuditAction, AuditStatus } from '../services/audit.service.js';

// ============================================
// API KEY AUTHENTICATION MIDDLEWARE
// ============================================

declare global {
    namespace Express {
        interface Request {
            apiKey?: {
                id: string;
                userId: string;
                scopes: string[];
            };
        }
    }
}

/**
 * Authenticate request using API key
 * Looks for key in X-API-Key header
 */
export async function authenticateApiKey(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const apiKeyHeader = req.headers['x-api-key'];

        if (!apiKeyHeader || typeof apiKeyHeader !== 'string') {
            res.status(401).json({
                success: false,
                error: 'API key is required',
                code: 'MISSING_API_KEY',
            });
            return;
        }

        // Hash the provided key
        const keyHash = sha256(apiKeyHeader);

        // Find key in database
        const apiKey = await prisma.apiKey.findUnique({
            where: { keyHash },
            include: {
                user: {
                    select: {
                        id: true,
                        email: true,
                        role: true,
                    },
                },
            },
        });

        if (!apiKey) {
            await createAuditLog({
                action: AuditAction.SUSPICIOUS_ACTIVITY,
                status: AuditStatus.FAILURE,
                details: {
                    reason: 'Invalid API key',
                    keyPrefix: apiKeyHeader.slice(0, 8),
                },
                req,
            });

            res.status(401).json({
                success: false,
                error: 'Invalid API key',
                code: 'INVALID_API_KEY',
            });
            return;
        }

        // Check if key is active
        if (!apiKey.isActive) {
            res.status(401).json({
                success: false,
                error: 'API key is disabled',
                code: 'API_KEY_DISABLED',
            });
            return;
        }

        // Check expiration
        if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
            res.status(401).json({
                success: false,
                error: 'API key has expired',
                code: 'API_KEY_EXPIRED',
            });
            return;
        }

        // Update last used
        const clientIp =
            req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ||
            req.ip ||
            'unknown';

        await prisma.apiKey.update({
            where: { id: apiKey.id },
            data: {
                lastUsedAt: new Date(),
                lastUsedIp: clientIp,
            },
        });

        // Set API key info on request
        req.apiKey = {
            id: apiKey.id,
            userId: apiKey.userId,
            scopes: apiKey.scopes,
        };

        // Also set user info for compatibility
        req.user = {
            sub: apiKey.userId,
            email: apiKey.user.email,
            type: 'access' as const,
            jti: apiKey.id,
        };

        next();
    } catch (error) {
        console.error('API key authentication error:', error);
        res.status(500).json({
            success: false,
            error: 'Authentication failed',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Require specific API key scope
 */
export function requireScope(...requiredScopes: string[]) {
    return (req: Request, res: Response, next: NextFunction): void => {
        if (!req.apiKey) {
            res.status(401).json({
                success: false,
                error: 'API key authentication required',
                code: 'NOT_AUTHENTICATED',
            });
            return;
        }

        const hasAllScopes = requiredScopes.every((scope) =>
            req.apiKey!.scopes.includes(scope)
        );

        if (!hasAllScopes) {
            res.status(403).json({
                success: false,
                error: 'Insufficient API key scope',
                code: 'INSUFFICIENT_SCOPE',
                requiredScopes,
                currentScopes: req.apiKey.scopes,
            });
            return;
        }

        next();
    };
}

/**
 * Accept either JWT or API key authentication
 */
export async function authenticateAny(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    // Check for API key first
    if (req.headers['x-api-key']) {
        return authenticateApiKey(req, res, next);
    }

    // Fall back to JWT auth (already handled by auth.middleware)
    if (!req.user) {
        res.status(401).json({
            success: false,
            error: 'Authentication required (JWT or API key)',
            code: 'NOT_AUTHENTICATED',
        });
        return;
    }

    next();
}

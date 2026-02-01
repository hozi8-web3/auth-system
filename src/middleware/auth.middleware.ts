import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, AccessTokenPayload } from '../utils/jwt.js';

// ============================================
// EXTEND EXPRESS REQUEST TYPE
// ============================================

declare global {
    namespace Express {
        interface Request {
            user?: AccessTokenPayload;
        }
    }
}

// ============================================
// AUTH MIDDLEWARE
// ============================================

/**
 * Require valid access token
 */
export function requireAuth(
    req: Request,
    res: Response,
    next: NextFunction
): void {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            res.status(401).json({
                success: false,
                error: 'Authorization header is required',
                code: 'MISSING_AUTH_HEADER',
            });
            return;
        }

        if (!authHeader.startsWith('Bearer ')) {
            res.status(401).json({
                success: false,
                error: 'Invalid authorization format. Use: Bearer <token>',
                code: 'INVALID_AUTH_FORMAT',
            });
            return;
        }

        const token = authHeader.slice(7);

        if (!token) {
            res.status(401).json({
                success: false,
                error: 'Access token is required',
                code: 'MISSING_TOKEN',
            });
            return;
        }

        // Verify token
        const payload = verifyAccessToken(token);
        req.user = payload;
        next();
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid token';

        if (message.includes('expired')) {
            res.status(401).json({
                success: false,
                error: 'Access token has expired',
                code: 'TOKEN_EXPIRED',
            });
            return;
        }

        res.status(401).json({
            success: false,
            error: 'Invalid access token',
            code: 'INVALID_TOKEN',
        });
    }
}

/**
 * Optional auth - doesn't require token but will parse it if present
 */
export function optionalAuth(
    req: Request,
    _res: Response,
    next: NextFunction
): void {
    try {
        const authHeader = req.headers.authorization;

        if (authHeader?.startsWith('Bearer ')) {
            const token = authHeader.slice(7);
            if (token) {
                const payload = verifyAccessToken(token);
                req.user = payload;
            }
        }
    } catch {
        // Ignore errors - auth is optional
    }
    next();
}

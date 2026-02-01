import { Request, Response } from 'express';
import { sendMagicLink, verifyMagicLink } from '../services/magicLink.service.js';
import webauthnService from '../services/webauthn.service.js';
import { generateTokenPair } from '../utils/jwt.js';
import { createAuditLog, AuditAction, AuditStatus } from '../services/audit.service.js';
import prisma from '../config/database.js';

// ============================================
// HELPER FUNCTIONS
// ============================================

function getClientIp(req: Request): string {
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
        const ips = typeof forwardedFor === 'string' ? forwardedFor : forwardedFor[0];
        return ips?.split(',')[0]?.trim() || req.ip || 'unknown';
    }
    return req.ip || 'unknown';
}

// ============================================
// MAGIC LINK (PASSWORDLESS) CONTROLLER
// ============================================

/**
 * Request magic link
 */
export async function requestMagicLink(req: Request, res: Response): Promise<void> {
    try {
        const { email } = req.body;

        await sendMagicLink(email);

        // Don't reveal if email exists
        res.json({
            success: true,
            message: 'If an account exists, a magic link has been sent',
        });
    } catch (error) {
        console.error('Magic link request error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send magic link',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Verify magic link and login
 */
export async function verifyMagicLinkToken(req: Request, res: Response): Promise<void> {
    try {
        const { token } = req.body;

        const result = await verifyMagicLink(token);

        if (!result.valid) {
            res.status(400).json({
                success: false,
                error: result.error || 'Invalid magic link',
                code: 'INVALID_MAGIC_LINK',
            });
            return;
        }

        // Get user
        const user = await prisma.user.findUnique({
            where: { id: result.userId },
        });

        if (!user) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        // Generate tokens
        const ipAddress = getClientIp(req);
        const userAgent = req.headers['user-agent'];

        const tokens = await generateTokenPair(
            user.id,
            user.email,
            userAgent,
            ipAddress
        );

        await createAuditLog({
            userId: user.id,
            action: AuditAction.LOGIN,
            status: AuditStatus.SUCCESS,
            details: { method: 'magic_link' },
            req,
        });

        res.json({
            success: true,
            data: {
                accessToken: tokens.accessToken,
                accessTokenExpiry: tokens.accessTokenExpiry,
                user: {
                    id: user.id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                },
            },
        });
    } catch (error) {
        console.error('Magic link verification error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to verify magic link',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// WEBAUTHN/PASSKEY CONTROLLER
// ============================================

/**
 * Get WebAuthn registration options
 */
export async function getWebAuthnRegistrationOptions(
    req: Request,
    res: Response
): Promise<void> {
    try {
        const userId = req.user!.sub;
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { email: true, firstName: true, lastName: true },
        });

        if (!user) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        const displayName = [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email;
        const options = await webauthnService.generateRegistrationOptions(
            userId,
            user.email,
            displayName
        );

        res.json({
            success: true,
            data: { options },
        });
    } catch (error) {
        console.error('WebAuthn registration options error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to generate registration options',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Verify WebAuthn registration
 */
export async function verifyWebAuthnRegistration(
    req: Request,
    res: Response
): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { credential, deviceName } = req.body;

        const result = await webauthnService.verifyRegistration(userId, credential, deviceName);

        if (!result.verified) {
            res.status(400).json({
                success: false,
                error: result.error || 'Registration verification failed',
                code: 'VERIFICATION_FAILED',
            });
            return;
        }

        await createAuditLog({
            userId,
            action: AuditAction.TWO_FACTOR_ENABLED,
            status: AuditStatus.SUCCESS,
            details: { method: 'webauthn', deviceName },
            req,
        });

        res.json({
            success: true,
            message: 'Passkey registered successfully',
        });
    } catch (error) {
        console.error('WebAuthn registration verification error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to verify registration',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Get WebAuthn authentication options
 */
export async function getWebAuthnAuthenticationOptions(
    req: Request,
    res: Response
): Promise<void> {
    try {
        const { email } = req.body;

        // Find user by email
        const user = email
            ? await prisma.user.findUnique({ where: { email } })
            : null;

        const options = await webauthnService.generateAuthenticationOptions(user?.id);

        res.json({
            success: true,
            data: { options },
        });
    } catch (error) {
        console.error('WebAuthn authentication options error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to generate authentication options',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Verify WebAuthn authentication (login)
 */
export async function verifyWebAuthnAuthentication(
    req: Request,
    res: Response
): Promise<void> {
    try {
        const { credential } = req.body;

        const result = await webauthnService.verifyAuthentication(credential);

        if (!result.verified || !result.userId) {
            res.status(401).json({
                success: false,
                error: result.error || 'Authentication failed',
                code: 'AUTH_FAILED',
            });
            return;
        }

        // Get user
        const user = await prisma.user.findUnique({
            where: { id: result.userId },
        });

        if (!user) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        // Generate tokens
        const ipAddress = getClientIp(req);
        const userAgent = req.headers['user-agent'];

        const tokens = await generateTokenPair(
            user.id,
            user.email,
            userAgent,
            ipAddress
        );

        await createAuditLog({
            userId: user.id,
            action: AuditAction.LOGIN,
            status: AuditStatus.SUCCESS,
            details: { method: 'webauthn' },
            req,
        });

        res.json({
            success: true,
            data: {
                accessToken: tokens.accessToken,
                accessTokenExpiry: tokens.accessTokenExpiry,
                user: {
                    id: user.id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                },
            },
        });
    } catch (error) {
        console.error('WebAuthn authentication error:', error);
        res.status(500).json({
            success: false,
            error: 'Authentication failed',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * List user's passkeys
 */
export async function listPasskeys(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;

        const credentials = await webauthnService.listCredentials(userId);

        res.json({
            success: true,
            data: { credentials },
        });
    } catch (error) {
        console.error('List passkeys error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to list passkeys',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Delete a passkey
 */
export async function deletePasskey(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { credentialId } = req.params;

        const deleted = await webauthnService.deleteCredential(userId, credentialId);

        if (!deleted) {
            res.status(404).json({
                success: false,
                error: 'Passkey not found',
                code: 'NOT_FOUND',
            });
            return;
        }

        await createAuditLog({
            userId,
            action: AuditAction.TWO_FACTOR_DISABLED,
            status: AuditStatus.SUCCESS,
            details: { method: 'webauthn', credentialId },
            req,
        });

        res.json({
            success: true,
            message: 'Passkey deleted successfully',
        });
    } catch (error) {
        console.error('Delete passkey error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete passkey',
            code: 'INTERNAL_ERROR',
        });
    }
}

export default {
    requestMagicLink,
    verifyMagicLinkToken,
    getWebAuthnRegistrationOptions,
    verifyWebAuthnRegistration,
    getWebAuthnAuthenticationOptions,
    verifyWebAuthnAuthentication,
    listPasskeys,
    deletePasskey,
};

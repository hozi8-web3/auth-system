import { Request, Response } from 'express';
import prisma from '../config/database.js';
import config from '../config/index.js';
import { verifyPassword } from '../utils/password.js';
import {
    generateTwoFactorSetup,
    verifyTotpCode,
    formatBackupCodes,
} from '../utils/twoFactor.js';
import {
    sendSecurityAlertEmail,
} from '../services/email.service.js';
import {
    createAuditLog,
    AuditAction,
    AuditStatus,
} from '../services/audit.service.js';
import { revokeAllSessions } from '../utils/jwt.js';

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
// SETUP 2FA
// ============================================

export async function setup2FA(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;

        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        if (user.twoFactorEnabled) {
            res.status(400).json({
                success: false,
                error: 'Two-factor authentication is already enabled',
                code: '2FA_ALREADY_ENABLED',
            });
            return;
        }

        // Generate 2FA setup data
        const setup = await generateTwoFactorSetup(
            user.email,
            config.jwt.issuer // Using issuer as encryption key
        );

        // Store encrypted secret temporarily (not enabled yet)
        await prisma.user.update({
            where: { id: userId },
            data: {
                twoFactorSecret: setup.secret,
                backupCodes: setup.backupCodesHashed,
            },
        });

        await createAuditLog({
            userId,
            action: AuditAction.TWO_FACTOR_SETUP,
            status: AuditStatus.SUCCESS,
            req,
        });

        res.json({
            success: true,
            data: {
                qrCode: setup.qrCodeDataUrl,
                secret: setup.otpauthUrl, // For manual entry
                backupCodes: formatBackupCodes(setup.backupCodes),
            },
            message: 'Scan the QR code with your authenticator app, then verify with a code to enable 2FA.',
        });
    } catch (error) {
        console.error('Setup 2FA error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to setup two-factor authentication',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// ENABLE 2FA
// ============================================

export async function enable2FA(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { code } = req.body as { code: string };

        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        if (user.twoFactorEnabled) {
            res.status(400).json({
                success: false,
                error: 'Two-factor authentication is already enabled',
                code: '2FA_ALREADY_ENABLED',
            });
            return;
        }

        if (!user.twoFactorSecret) {
            res.status(400).json({
                success: false,
                error: 'Please setup 2FA first',
                code: '2FA_NOT_SETUP',
            });
            return;
        }

        // Verify the code
        const isValid = verifyTotpCode(code, user.twoFactorSecret, config.jwt.issuer);

        if (!isValid) {
            await createAuditLog({
                userId,
                action: AuditAction.TWO_FACTOR_FAILED,
                status: AuditStatus.FAILURE,
                details: { reason: 'Invalid code during enable' },
                req,
            });

            res.status(400).json({
                success: false,
                error: 'Invalid verification code',
                code: 'INVALID_CODE',
            });
            return;
        }

        // Enable 2FA
        await prisma.user.update({
            where: { id: userId },
            data: {
                twoFactorEnabled: true,
            },
        });

        await createAuditLog({
            userId,
            action: AuditAction.TWO_FACTOR_ENABLED,
            status: AuditStatus.SUCCESS,
            req,
        });

        // Send security alert
        try {
            await sendSecurityAlertEmail(user.email, 'two_factor_enabled', {
                ipAddress: getClientIp(req),
                userAgent: req.headers['user-agent'],
            });
        } catch {
            // Ignore email errors
        }

        res.json({
            success: true,
            message: 'Two-factor authentication has been enabled',
        });
    } catch (error) {
        console.error('Enable 2FA error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to enable two-factor authentication',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// DISABLE 2FA
// ============================================

export async function disable2FA(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { password, code } = req.body as { password: string; code: string };

        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        if (!user.twoFactorEnabled) {
            res.status(400).json({
                success: false,
                error: 'Two-factor authentication is not enabled',
                code: '2FA_NOT_ENABLED',
            });
            return;
        }

        // Verify password
        const isValidPassword = await verifyPassword(password, user.passwordHash);
        if (!isValidPassword) {
            res.status(401).json({
                success: false,
                error: 'Invalid password',
                code: 'INVALID_PASSWORD',
            });
            return;
        }

        // Verify 2FA code
        const isValidCode = verifyTotpCode(code, user.twoFactorSecret!, config.jwt.issuer);
        if (!isValidCode) {
            res.status(400).json({
                success: false,
                error: 'Invalid verification code',
                code: 'INVALID_CODE',
            });
            return;
        }

        // Disable 2FA
        await prisma.user.update({
            where: { id: userId },
            data: {
                twoFactorEnabled: false,
                twoFactorSecret: null,
                backupCodes: [],
            },
        });

        // Revoke all sessions for security
        await revokeAllSessions(userId);

        await createAuditLog({
            userId,
            action: AuditAction.TWO_FACTOR_DISABLED,
            status: AuditStatus.SUCCESS,
            req,
        });

        // Send security alert
        try {
            await sendSecurityAlertEmail(user.email, 'two_factor_disabled', {
                ipAddress: getClientIp(req),
                userAgent: req.headers['user-agent'],
            });
        } catch {
            // Ignore email errors
        }

        res.json({
            success: true,
            message: 'Two-factor authentication has been disabled. All sessions have been revoked.',
        });
    } catch (error) {
        console.error('Disable 2FA error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to disable two-factor authentication',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// REGENERATE BACKUP CODES
// ============================================

export async function regenerateBackupCodes(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { password, code } = req.body as { password: string; code: string };

        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        if (!user.twoFactorEnabled) {
            res.status(400).json({
                success: false,
                error: 'Two-factor authentication must be enabled first',
                code: '2FA_NOT_ENABLED',
            });
            return;
        }

        // Verify password
        const isValidPassword = await verifyPassword(password, user.passwordHash);
        if (!isValidPassword) {
            res.status(401).json({
                success: false,
                error: 'Invalid password',
                code: 'INVALID_PASSWORD',
            });
            return;
        }

        // Verify 2FA code
        const isValidCode = verifyTotpCode(code, user.twoFactorSecret!, config.jwt.issuer);
        if (!isValidCode) {
            res.status(400).json({
                success: false,
                error: 'Invalid verification code',
                code: 'INVALID_CODE',
            });
            return;
        }

        // Generate new backup codes
        const setup = await generateTwoFactorSetup(
            user.email,
            config.jwt.issuer
        );

        // Update backup codes only
        await prisma.user.update({
            where: { id: userId },
            data: {
                backupCodes: setup.backupCodesHashed,
            },
        });

        await createAuditLog({
            userId,
            action: AuditAction.TWO_FACTOR_SETUP,
            status: AuditStatus.SUCCESS,
            details: { reason: 'Backup codes regenerated' },
            req,
        });

        res.json({
            success: true,
            data: {
                backupCodes: formatBackupCodes(setup.backupCodes),
            },
            message: 'New backup codes generated. Save these codes securely.',
        });
    } catch (error) {
        console.error('Regenerate backup codes error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to regenerate backup codes',
            code: 'INTERNAL_ERROR',
        });
    }
}

export default {
    setup2FA,
    enable2FA,
    disable2FA,
    regenerateBackupCodes,
};

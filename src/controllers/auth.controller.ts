import { Request, Response } from 'express';
import prisma from '../config/database.js';
import config from '../config/index.js';
import { hashPassword, verifyPassword, validatePasswordStrength } from '../utils/password.js';
import { generateSecureToken, sha256 } from '../utils/crypto.js';
import {
    generateTokenPair,
    rotateRefreshToken,
    revokeSession,
    revokeAllSessions,
    verifyRefreshToken,
    validateRefreshToken
} from '../utils/jwt.js';
import {
    generateTwoFactorSetup,
    verifyTwoFactor,
    formatBackupCodes,
} from '../utils/twoFactor.js';
import {
    sendVerificationEmail,
    sendPasswordResetEmail,
    sendSecurityAlertEmail,
} from '../services/email.service.js';
import {
    createAuditLog,
    AuditAction,
    AuditStatus,
} from '../services/audit.service.js';
import type {
    RegisterInput,
    LoginInput,
    ForgotPasswordInput,
    ResetPasswordInput,
    ChangePasswordInput,
} from '../validators/auth.validator.js';

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

function setRefreshTokenCookie(res: Response, refreshToken: string, expiresAt: Date): void {
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        domain: config.cookie.domain,
        expires: expiresAt,
        path: '/api/v1/auth',
    });
}

function clearRefreshTokenCookie(res: Response): void {
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        domain: config.cookie.domain,
        path: '/api/v1/auth',
    });
}

// ============================================
// REGISTER
// ============================================

export async function register(req: Request, res: Response): Promise<void> {
    try {
        const { email, password, firstName, lastName } = req.body as RegisterInput;

        // Validate password strength
        const passwordValidation = validatePasswordStrength(password);
        if (!passwordValidation.isValid) {
            res.status(400).json({
                success: false,
                error: 'Password does not meet security requirements',
                code: 'WEAK_PASSWORD',
                details: passwordValidation.errors,
            });
            return;
        }

        // Check if user exists
        const existingUser = await prisma.user.findUnique({
            where: { email },
        });

        if (existingUser) {
            // Don't reveal if email exists - security best practice
            res.status(200).json({
                success: true,
                message: 'If this email is not registered, you will receive a verification email shortly.',
            });
            return;
        }

        // Hash password
        const passwordHash = await hashPassword(password);

        // Generate email verification token
        const emailVerifyToken = generateSecureToken(32);
        const emailVerifyExpires = new Date();
        emailVerifyExpires.setHours(
            emailVerifyExpires.getHours() + config.email.verificationExpiryHours
        );

        // Create user
        const user = await prisma.user.create({
            data: {
                email,
                passwordHash,
                firstName,
                lastName,
                emailVerifyToken: sha256(emailVerifyToken),
                emailVerifyExpires,
            },
        });

        // Send verification email
        try {
            await sendVerificationEmail(email, emailVerifyToken, firstName);
        } catch (emailError) {
            console.error('Failed to send verification email:', emailError);
        }

        // Audit log
        await createAuditLog({
            userId: user.id,
            action: AuditAction.REGISTER,
            status: AuditStatus.SUCCESS,
            req,
        });

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please check your email to verify your account.',
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({
            success: false,
            error: 'Registration failed',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// LOGIN
// ============================================

export async function login(req: Request, res: Response): Promise<void> {
    try {
        const { email, password, twoFactorCode } = req.body as LoginInput;
        const ipAddress = getClientIp(req);
        const userAgent = req.headers['user-agent'];

        // Find user
        const user = await prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            await createAuditLog({
                action: AuditAction.LOGIN_FAILED,
                status: AuditStatus.FAILURE,
                details: { email, reason: 'User not found' },
                req,
            });

            res.status(401).json({
                success: false,
                error: 'Invalid email or password',
                code: 'INVALID_CREDENTIALS',
            });
            return;
        }

        // Check if account is locked
        if (user.lockedUntil && user.lockedUntil > new Date()) {
            const minutesRemaining = Math.ceil(
                (user.lockedUntil.getTime() - Date.now()) / 60000
            );

            res.status(423).json({
                success: false,
                error: `Account is locked. Try again in ${minutesRemaining} minutes.`,
                code: 'ACCOUNT_LOCKED',
            });
            return;
        }

        // Verify password
        const isValidPassword = await verifyPassword(password, user.passwordHash);

        if (!isValidPassword) {
            // Increment failed attempts
            const newFailedAttempts = user.failedLoginAttempts + 1;
            const shouldLock = newFailedAttempts >= config.security.maxLoginAttempts;

            await prisma.user.update({
                where: { id: user.id },
                data: {
                    failedLoginAttempts: newFailedAttempts,
                    lockedUntil: shouldLock
                        ? new Date(Date.now() + config.security.lockoutDurationMinutes * 60000)
                        : null,
                },
            });

            if (shouldLock) {
                await createAuditLog({
                    userId: user.id,
                    action: AuditAction.ACCOUNT_LOCKED,
                    status: AuditStatus.SUCCESS,
                    details: { reason: 'Too many failed login attempts' },
                    req,
                });
            }

            await createAuditLog({
                userId: user.id,
                action: AuditAction.LOGIN_FAILED,
                status: AuditStatus.FAILURE,
                details: { reason: 'Invalid password' },
                req,
            });

            res.status(401).json({
                success: false,
                error: 'Invalid email or password',
                code: 'INVALID_CREDENTIALS',
                ...(shouldLock && {
                    message: `Account locked due to too many failed attempts. Try again in ${config.security.lockoutDurationMinutes} minutes.`,
                }),
            });
            return;
        }

        // Check email verification
        if (!user.emailVerified) {
            res.status(403).json({
                success: false,
                error: 'Please verify your email before logging in',
                code: 'EMAIL_NOT_VERIFIED',
            });
            return;
        }

        // Check 2FA
        if (user.twoFactorEnabled) {
            if (!twoFactorCode) {
                res.status(200).json({
                    success: true,
                    requiresTwoFactor: true,
                    message: 'Two-factor authentication required',
                });
                return;
            }

            // Verify 2FA code
            const twoFactorResult = verifyTwoFactor(
                twoFactorCode,
                user.twoFactorSecret!,
                user.backupCodes,
                config.jwt.issuer // Using issuer as encryption key
            );

            if (!twoFactorResult.valid) {
                await createAuditLog({
                    userId: user.id,
                    action: AuditAction.TWO_FACTOR_FAILED,
                    status: AuditStatus.FAILURE,
                    req,
                });

                res.status(401).json({
                    success: false,
                    error: 'Invalid two-factor code',
                    code: 'INVALID_2FA_CODE',
                });
                return;
            }

            // Update backup codes if one was used
            if (twoFactorResult.usedBackupCode) {
                await prisma.user.update({
                    where: { id: user.id },
                    data: { backupCodes: twoFactorResult.remainingBackupCodes },
                });

                await createAuditLog({
                    userId: user.id,
                    action: AuditAction.BACKUP_CODE_USED,
                    status: AuditStatus.SUCCESS,
                    details: { remainingCodes: twoFactorResult.remainingBackupCodes.length },
                    req,
                });
            }
        }

        // Reset failed attempts and update last login
        await prisma.user.update({
            where: { id: user.id },
            data: {
                failedLoginAttempts: 0,
                lockedUntil: null,
                lastLoginAt: new Date(),
                lastLoginIp: ipAddress,
            },
        });

        // Generate tokens
        const tokens = await generateTokenPair(user.id, user.email, userAgent, ipAddress);

        // Set refresh token cookie
        setRefreshTokenCookie(res, tokens.refreshToken, tokens.refreshTokenExpiry);

        // Audit log
        await createAuditLog({
            userId: user.id,
            action: AuditAction.LOGIN,
            status: AuditStatus.SUCCESS,
            req,
        });

        // Send security alert for new login
        try {
            await sendSecurityAlertEmail(user.email, 'new_login', {
                ipAddress,
                userAgent,
            });
        } catch {
            // Ignore email errors
        }

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
                    emailVerified: user.emailVerified,
                    twoFactorEnabled: user.twoFactorEnabled,
                },
            },
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Login failed',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// LOGOUT
// ============================================

export async function logout(req: Request, res: Response): Promise<void> {
    try {
        // Get refresh token from cookie or body
        const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (refreshToken) {
            try {
                const payload = verifyRefreshToken(refreshToken);
                await revokeSession(payload.sessionId);

                await createAuditLog({
                    userId: payload.sub,
                    action: AuditAction.LOGOUT,
                    status: AuditStatus.SUCCESS,
                    req,
                });
            } catch {
                // Ignore invalid token - user is logging out anyway
            }
        }

        clearRefreshTokenCookie(res);

        res.json({
            success: true,
            message: 'Logged out successfully',
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            success: false,
            error: 'Logout failed',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// REFRESH TOKEN
// ============================================

export async function refreshToken(req: Request, res: Response): Promise<void> {
    try {
        const token = req.cookies.refreshToken || req.body.refreshToken;
        const ipAddress = getClientIp(req);
        const userAgent = req.headers['user-agent'];

        if (!token) {
            res.status(401).json({
                success: false,
                error: 'Refresh token is required',
                code: 'MISSING_REFRESH_TOKEN',
            });
            return;
        }

        // Rotate token
        const tokens = await rotateRefreshToken(token, userAgent, ipAddress);

        // Set new refresh token cookie
        setRefreshTokenCookie(res, tokens.refreshToken, tokens.refreshTokenExpiry);

        res.json({
            success: true,
            data: {
                accessToken: tokens.accessToken,
                accessTokenExpiry: tokens.accessTokenExpiry,
            },
        });
    } catch (error) {
        clearRefreshTokenCookie(res);

        const message = error instanceof Error ? error.message : 'Invalid refresh token';

        if (message.includes('reuse')) {
            res.status(401).json({
                success: false,
                error: 'Session compromised. All sessions have been revoked.',
                code: 'TOKEN_REUSE_DETECTED',
            });
            return;
        }

        res.status(401).json({
            success: false,
            error: 'Invalid or expired refresh token',
            code: 'INVALID_REFRESH_TOKEN',
        });
    }
}

// ============================================
// VERIFY EMAIL
// ============================================

export async function verifyEmail(req: Request, res: Response): Promise<void> {
    try {
        const { token } = req.query as { token: string };

        if (!token) {
            res.status(400).json({
                success: false,
                error: 'Verification token is required',
                code: 'MISSING_TOKEN',
            });
            return;
        }

        const tokenHash = sha256(token);

        const user = await prisma.user.findFirst({
            where: {
                emailVerifyToken: tokenHash,
                emailVerifyExpires: { gt: new Date() },
            },
        });

        if (!user) {
            res.status(400).json({
                success: false,
                error: 'Invalid or expired verification token',
                code: 'INVALID_TOKEN',
            });
            return;
        }

        await prisma.user.update({
            where: { id: user.id },
            data: {
                emailVerified: true,
                emailVerifyToken: null,
                emailVerifyExpires: null,
            },
        });

        await createAuditLog({
            userId: user.id,
            action: AuditAction.EMAIL_VERIFIED,
            status: AuditStatus.SUCCESS,
            req,
        });

        // Redirect to frontend or return success
        if (config.frontendUrl) {
            res.redirect(`${config.frontendUrl}/email-verified`);
        } else {
            res.json({
                success: true,
                message: 'Email verified successfully',
            });
        }
    } catch (error) {
        console.error('Verify email error:', error);
        res.status(500).json({
            success: false,
            error: 'Email verification failed',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// FORGOT PASSWORD
// ============================================

export async function forgotPassword(req: Request, res: Response): Promise<void> {
    try {
        const { email } = req.body as ForgotPasswordInput;

        // Always return success to prevent email enumeration
        const successResponse = {
            success: true,
            message: 'If an account exists with this email, you will receive a password reset link.',
        };

        const user = await prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            res.json(successResponse);
            return;
        }

        // Generate reset token
        const resetToken = generateSecureToken(32);
        const resetExpires = new Date();
        resetExpires.setHours(
            resetExpires.getHours() + config.email.passwordResetExpiryHours
        );

        await prisma.user.update({
            where: { id: user.id },
            data: {
                passwordResetToken: sha256(resetToken),
                passwordResetExpires: resetExpires,
            },
        });

        // Send reset email
        try {
            await sendPasswordResetEmail(email, resetToken, user.firstName || undefined);
        } catch (emailError) {
            console.error('Failed to send password reset email:', emailError);
        }

        await createAuditLog({
            userId: user.id,
            action: AuditAction.PASSWORD_RESET_REQUEST,
            status: AuditStatus.SUCCESS,
            req,
        });

        res.json(successResponse);
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            error: 'Password reset request failed',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// RESET PASSWORD
// ============================================

export async function resetPassword(req: Request, res: Response): Promise<void> {
    try {
        const { token, password } = req.body as ResetPasswordInput;

        // Validate password strength
        const passwordValidation = validatePasswordStrength(password);
        if (!passwordValidation.isValid) {
            res.status(400).json({
                success: false,
                error: 'Password does not meet security requirements',
                code: 'WEAK_PASSWORD',
                details: passwordValidation.errors,
            });
            return;
        }

        const tokenHash = sha256(token);

        const user = await prisma.user.findFirst({
            where: {
                passwordResetToken: tokenHash,
                passwordResetExpires: { gt: new Date() },
            },
        });

        if (!user) {
            res.status(400).json({
                success: false,
                error: 'Invalid or expired reset token',
                code: 'INVALID_TOKEN',
            });
            return;
        }

        // Hash new password
        const passwordHash = await hashPassword(password);

        // Update password and clear reset token
        await prisma.user.update({
            where: { id: user.id },
            data: {
                passwordHash,
                passwordResetToken: null,
                passwordResetExpires: null,
                failedLoginAttempts: 0,
                lockedUntil: null,
            },
        });

        // Revoke all existing sessions for security
        await revokeAllSessions(user.id);

        await createAuditLog({
            userId: user.id,
            action: AuditAction.PASSWORD_RESET,
            status: AuditStatus.SUCCESS,
            req,
        });

        // Send security alert
        try {
            await sendSecurityAlertEmail(user.email, 'password_changed', {
                ipAddress: getClientIp(req),
                userAgent: req.headers['user-agent'],
            });
        } catch {
            // Ignore email errors
        }

        res.json({
            success: true,
            message: 'Password reset successfully. Please log in with your new password.',
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            error: 'Password reset failed',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// GET CURRENT USER
// ============================================

export async function me(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;

        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                emailVerified: true,
                twoFactorEnabled: true,
                lastLoginAt: true,
                createdAt: true,
            },
        });

        if (!user) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        res.json({
            success: true,
            data: { user },
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get user data',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// CHANGE PASSWORD
// ============================================

export async function changePassword(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { currentPassword, newPassword } = req.body as ChangePasswordInput;

        // Validate new password strength
        const passwordValidation = validatePasswordStrength(newPassword);
        if (!passwordValidation.isValid) {
            res.status(400).json({
                success: false,
                error: 'New password does not meet security requirements',
                code: 'WEAK_PASSWORD',
                details: passwordValidation.errors,
            });
            return;
        }

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

        // Verify current password
        const isValidPassword = await verifyPassword(currentPassword, user.passwordHash);
        if (!isValidPassword) {
            res.status(401).json({
                success: false,
                error: 'Current password is incorrect',
                code: 'INVALID_PASSWORD',
            });
            return;
        }

        // Hash new password
        const passwordHash = await hashPassword(newPassword);

        await prisma.user.update({
            where: { id: userId },
            data: { passwordHash },
        });

        await createAuditLog({
            userId,
            action: AuditAction.PASSWORD_CHANGE,
            status: AuditStatus.SUCCESS,
            req,
        });

        // Send security alert
        try {
            await sendSecurityAlertEmail(user.email, 'password_changed', {
                ipAddress: getClientIp(req),
                userAgent: req.headers['user-agent'],
            });
        } catch {
            // Ignore email errors
        }

        res.json({
            success: true,
            message: 'Password changed successfully',
        });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to change password',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// REVOKE ALL SESSIONS
// ============================================

export async function revokeAllUserSessions(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;

        await revokeAllSessions(userId);

        await createAuditLog({
            userId,
            action: AuditAction.ALL_SESSIONS_REVOKED,
            status: AuditStatus.SUCCESS,
            req,
        });

        // Get user email for alert
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { email: true },
        });

        if (user) {
            try {
                await sendSecurityAlertEmail(user.email, 'sessions_revoked', {
                    ipAddress: getClientIp(req),
                    userAgent: req.headers['user-agent'],
                });
            } catch {
                // Ignore email errors
            }
        }

        clearRefreshTokenCookie(res);

        res.json({
            success: true,
            message: 'All sessions have been revoked',
        });
    } catch (error) {
        console.error('Revoke sessions error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to revoke sessions',
            code: 'INTERNAL_ERROR',
        });
    }
}

export default {
    register,
    login,
    logout,
    refreshToken,
    verifyEmail,
    forgotPassword,
    resetPassword,
    me,
    changePassword,
    revokeAllUserSessions,
};

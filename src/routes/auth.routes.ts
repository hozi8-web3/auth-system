import { Router } from 'express';
import * as authController from '../controllers/auth.controller.js';
import * as twoFactorController from '../controllers/twoFactor.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import { validateBody, validateQuery } from '../middleware/validate.middleware.js';
import {
    authLimiter,
    strictLimiter,
    registerLimiter,
    passwordResetLimiter,
} from '../middleware/rateLimit.middleware.js';
import {
    registerSchema,
    loginSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
    changePasswordSchema,
    enableTwoFactorSchema,
    verifyEmailSchema,
} from '../validators/auth.validator.js';
import { z } from 'zod';

const router = Router();

// ============================================
// PUBLIC ROUTES (No auth required)
// ============================================

/**
 * @route   POST /auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post(
    '/register',
    registerLimiter,
    validateBody(registerSchema),
    authController.register
);

/**
 * @route   POST /auth/login
 * @desc    Login user
 * @access  Public
 */
router.post(
    '/login',
    authLimiter,
    validateBody(loginSchema),
    authController.login
);

/**
 * @route   POST /auth/logout
 * @desc    Logout user
 * @access  Public
 */
router.post('/logout', authController.logout);

/**
 * @route   POST /auth/refresh
 * @desc    Refresh access token
 * @access  Public (requires valid refresh token)
 */
router.post('/refresh', authLimiter, authController.refreshToken);

/**
 * @route   GET /auth/verify-email
 * @desc    Verify email address
 * @access  Public
 */
router.get(
    '/verify-email',
    validateQuery(verifyEmailSchema),
    authController.verifyEmail
);

/**
 * @route   POST /auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post(
    '/forgot-password',
    passwordResetLimiter,
    validateBody(forgotPasswordSchema),
    authController.forgotPassword
);

/**
 * @route   POST /auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post(
    '/reset-password',
    passwordResetLimiter,
    validateBody(resetPasswordSchema),
    authController.resetPassword
);

// ============================================
// PROTECTED ROUTES (Auth required)
// ============================================

/**
 * @route   GET /auth/me
 * @desc    Get current user
 * @access  Private
 */
router.get('/me', requireAuth, authController.me);

/**
 * @route   POST /auth/change-password
 * @desc    Change password
 * @access  Private
 */
router.post(
    '/change-password',
    requireAuth,
    strictLimiter,
    validateBody(changePasswordSchema),
    authController.changePassword
);

/**
 * @route   DELETE /auth/sessions
 * @desc    Revoke all sessions
 * @access  Private
 */
router.delete(
    '/sessions',
    requireAuth,
    strictLimiter,
    authController.revokeAllUserSessions
);

// ============================================
// TWO-FACTOR AUTHENTICATION ROUTES
// ============================================

/**
 * @route   POST /auth/2fa/setup
 * @desc    Setup 2FA (get QR code and backup codes)
 * @access  Private
 */
router.post(
    '/2fa/setup',
    requireAuth,
    strictLimiter,
    twoFactorController.setup2FA
);

/**
 * @route   POST /auth/2fa/enable
 * @desc    Enable 2FA with verification code
 * @access  Private
 */
router.post(
    '/2fa/enable',
    requireAuth,
    strictLimiter,
    validateBody(enableTwoFactorSchema),
    twoFactorController.enable2FA
);

/**
 * @route   POST /auth/2fa/disable
 * @desc    Disable 2FA
 * @access  Private
 */
router.post(
    '/2fa/disable',
    requireAuth,
    strictLimiter,
    validateBody(
        z.object({
            password: z.string().min(1, 'Password is required'),
            code: z.string().min(6, 'Code is required'),
        })
    ),
    twoFactorController.disable2FA
);

/**
 * @route   POST /auth/2fa/backup-codes
 * @desc    Regenerate backup codes
 * @access  Private
 */
router.post(
    '/2fa/backup-codes',
    requireAuth,
    strictLimiter,
    validateBody(
        z.object({
            password: z.string().min(1, 'Password is required'),
            code: z.string().min(6, 'Code is required'),
        })
    ),
    twoFactorController.regenerateBackupCodes
);

export default router;

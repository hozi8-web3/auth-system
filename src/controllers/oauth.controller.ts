import { Request, Response } from 'express';
import { OAuthProvider } from '@prisma/client';
import prisma from '../config/database.js';
import {
    generateOAuthState,
    verifyOAuthState,
    getOAuthAuthorizationUrl,
    exchangeCodeForTokens,
    getOAuthUserInfo,
} from '../services/oauth.service.js';
import { generateTokenPair } from '../utils/jwt.js';
import { createAuditLog, AuditAction, AuditStatus } from '../services/audit.service.js';
import { encrypt } from '../utils/crypto.js';
import config from '../config/index.js';

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
// INITIATE OAUTH
// ============================================

/**
 * Start OAuth flow - redirect to provider
 */
export async function initiateOAuth(req: Request, res: Response): Promise<void> {
    try {
        const { provider } = req.params;

        if (!['google', 'github', 'microsoft'].includes(provider)) {
            res.status(400).json({
                success: false,
                error: 'Invalid OAuth provider',
                code: 'INVALID_PROVIDER',
            });
            return;
        }

        // Generate state for CSRF protection
        const state = await generateOAuthState(provider);

        // Get authorization URL
        const authUrl = getOAuthAuthorizationUrl(provider, state);

        res.json({
            success: true,
            data: { authUrl },
        });
    } catch (error) {
        console.error('OAuth initiation error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to initiate OAuth',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// OAUTH CALLBACK
// ============================================

/**
 * Handle OAuth callback from provider
 */
export async function handleOAuthCallback(req: Request, res: Response): Promise<void> {
    try {
        const { provider } = req.params;
        const { code, state, error } = req.query;

        // Handle OAuth error
        if (error) {
            res.redirect(`${config.frontendUrl}/auth/error?error=${error}`);
            return;
        }

        // Validate state
        if (!state || typeof state !== 'string') {
            res.redirect(`${config.frontendUrl}/auth/error?error=missing_state`);
            return;
        }

        const isValidState = await verifyOAuthState(state, provider);
        if (!isValidState) {
            res.redirect(`${config.frontendUrl}/auth/error?error=invalid_state`);
            return;
        }

        // Validate code
        if (!code || typeof code !== 'string') {
            res.redirect(`${config.frontendUrl}/auth/error?error=missing_code`);
            return;
        }

        // Exchange code for tokens
        const tokens = await exchangeCodeForTokens(provider, code);

        // Get user info from provider
        const userInfo = await getOAuthUserInfo(provider, tokens.accessToken);

        if (!userInfo.email) {
            res.redirect(`${config.frontendUrl}/auth/error?error=no_email`);
            return;
        }

        // Find or create user
        let user = await prisma.user.findUnique({
            where: { email: userInfo.email },
        });

        const isNewUser = !user;

        if (!user) {
            // Create new user
            user = await prisma.user.create({
                data: {
                    email: userInfo.email,
                    firstName: userInfo.firstName || userInfo.name?.split(' ')[0],
                    lastName: userInfo.lastName || userInfo.name?.split(' ').slice(1).join(' '),
                    avatarUrl: userInfo.avatarUrl,
                    emailVerified: true, // OAuth emails are verified by provider
                },
            });
        }

        // Find or create OAuth account link
        const oauthProvider = provider.toUpperCase() as OAuthProvider;

        let oauthAccount = await prisma.oAuthAccount.findUnique({
            where: {
                provider_providerAccountId: {
                    provider: oauthProvider,
                    providerAccountId: userInfo.id,
                },
            },
        });

        if (!oauthAccount) {
            // Link OAuth account to user
            oauthAccount = await prisma.oAuthAccount.create({
                data: {
                    userId: user.id,
                    provider: oauthProvider,
                    providerAccountId: userInfo.id,
                    accessToken: encrypt(tokens.accessToken, config.jwt.issuer),
                    refreshToken: tokens.refreshToken
                        ? encrypt(tokens.refreshToken, config.jwt.issuer)
                        : null,
                    tokenExpiry: tokens.expiresIn
                        ? new Date(Date.now() + tokens.expiresIn * 1000)
                        : null,
                    providerEmail: userInfo.email,
                    providerName: userInfo.name,
                    providerAvatar: userInfo.avatarUrl,
                },
            });
        } else if (oauthAccount.userId !== user.id) {
            // OAuth account linked to different user
            res.redirect(`${config.frontendUrl}/auth/error?error=account_mismatch`);
            return;
        }

        // Generate auth tokens
        const ipAddress = getClientIp(req);
        const userAgent = req.headers['user-agent'];

        const authTokens = await generateTokenPair(
            user.id,
            user.email,
            userAgent,
            ipAddress
        );

        // Audit log
        await createAuditLog({
            userId: user.id,
            action: isNewUser ? AuditAction.REGISTER : AuditAction.LOGIN,
            status: AuditStatus.SUCCESS,
            details: { provider, oauthAccountId: oauthAccount.id },
            req,
        });

        // Redirect to frontend with tokens
        const callbackUrl = new URL(`${config.frontendUrl}/auth/callback`);
        callbackUrl.searchParams.set('accessToken', authTokens.accessToken);
        callbackUrl.searchParams.set('expiresAt', authTokens.accessTokenExpiry.toISOString());

        // Set refresh token as HTTP-only cookie
        res.cookie('refreshToken', authTokens.refreshToken, {
            httpOnly: true,
            secure: config.cookie.secure,
            sameSite: config.cookie.sameSite,
            domain: config.cookie.domain,
            expires: authTokens.refreshTokenExpiry,
            path: '/api/v1/auth',
        });

        res.redirect(callbackUrl.toString());
    } catch (error) {
        console.error('OAuth callback error:', error);
        res.redirect(`${config.frontendUrl}/auth/error?error=callback_failed`);
    }
}

// ============================================
// LINK OAUTH ACCOUNT
// ============================================

/**
 * Link an OAuth account to existing user
 */
export async function linkOAuthAccount(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { provider } = req.params;

        if (!['google', 'github', 'microsoft'].includes(provider)) {
            res.status(400).json({
                success: false,
                error: 'Invalid OAuth provider',
                code: 'INVALID_PROVIDER',
            });
            return;
        }

        // Generate state with user ID for linking
        const state = await generateOAuthState(`link:${userId}:${provider}`);
        const authUrl = getOAuthAuthorizationUrl(provider, state);

        res.json({
            success: true,
            data: { authUrl },
        });
    } catch (error) {
        console.error('Link OAuth error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to initiate OAuth linking',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// UNLINK OAUTH ACCOUNT
// ============================================

/**
 * Unlink an OAuth account from user
 */
export async function unlinkOAuthAccount(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { provider } = req.params;

        const oauthProvider = provider.toUpperCase() as OAuthProvider;

        // Check if user has password or other OAuth accounts
        const user = await prisma.user.findUnique({
            where: { id: userId },
            include: {
                oauthAccounts: true,
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

        // Ensure user has another login method
        const hasPassword = !!user.passwordHash;
        const otherOAuthAccounts = user.oauthAccounts.filter(
            (acc) => acc.provider !== oauthProvider
        );

        if (!hasPassword && otherOAuthAccounts.length === 0) {
            res.status(400).json({
                success: false,
                error: 'Cannot unlink - no other login method available',
                code: 'NO_LOGIN_METHOD',
            });
            return;
        }

        // Delete OAuth account
        await prisma.oAuthAccount.deleteMany({
            where: {
                userId,
                provider: oauthProvider,
            },
        });

        res.json({
            success: true,
            message: `${provider} account unlinked successfully`,
        });
    } catch (error) {
        console.error('Unlink OAuth error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to unlink OAuth account',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// LIST LINKED ACCOUNTS
// ============================================

/**
 * Get user's linked OAuth accounts
 */
export async function getLinkedAccounts(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;

        const accounts = await prisma.oAuthAccount.findMany({
            where: { userId },
            select: {
                provider: true,
                providerEmail: true,
                providerName: true,
                providerAvatar: true,
                createdAt: true,
            },
        });

        res.json({
            success: true,
            data: { accounts },
        });
    } catch (error) {
        console.error('Get linked accounts error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get linked accounts',
            code: 'INTERNAL_ERROR',
        });
    }
}

export default {
    initiateOAuth,
    handleOAuthCallback,
    linkOAuthAccount,
    unlinkOAuthAccount,
    getLinkedAccounts,
};

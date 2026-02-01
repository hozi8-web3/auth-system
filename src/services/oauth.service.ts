import config from '../config/index.js';

// ============================================
// OAUTH2 CONFIGURATION
// ============================================

export interface OAuthConfig {
    clientId: string;
    clientSecret: string;
    authUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    scopes: string[];
    callbackUrl: string;
}

export const oauthProviders: Record<string, OAuthConfig> = {
    google: {
        clientId: process.env.GOOGLE_CLIENT_ID || '',
        clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
        authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
        scopes: ['email', 'profile'],
        callbackUrl: `${config.apiBaseUrl}/api/${config.apiVersion}/auth/oauth/google/callback`,
    },
    github: {
        clientId: process.env.GITHUB_CLIENT_ID || '',
        clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
        authUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
        userInfoUrl: 'https://api.github.com/user',
        scopes: ['user:email'],
        callbackUrl: `${config.apiBaseUrl}/api/${config.apiVersion}/auth/oauth/github/callback`,
    },
    microsoft: {
        clientId: process.env.MICROSOFT_CLIENT_ID || '',
        clientSecret: process.env.MICROSOFT_CLIENT_SECRET || '',
        authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
        scopes: ['openid', 'email', 'profile'],
        callbackUrl: `${config.apiBaseUrl}/api/${config.apiVersion}/auth/oauth/microsoft/callback`,
    },
};

// ============================================
// OAUTH STATE MANAGEMENT
// ============================================

import { getRedisClient } from '../config/redis.js';
import { generateSecureToken } from '../utils/crypto.js';

const STATE_EXPIRY_SECONDS = 600; // 10 minutes

/**
 * Generate OAuth state for CSRF protection
 */
export async function generateOAuthState(provider: string): Promise<string> {
    const state = generateSecureToken(32);
    const redis = getRedisClient();

    await redis.setex(
        `oauth:state:${state}`,
        STATE_EXPIRY_SECONDS,
        JSON.stringify({ provider, createdAt: Date.now() })
    );

    return state;
}

/**
 * Verify OAuth state
 */
export async function verifyOAuthState(
    state: string,
    expectedProvider: string
): Promise<boolean> {
    const redis = getRedisClient();
    const data = await redis.get(`oauth:state:${state}`);

    if (!data) return false;

    try {
        const parsed = JSON.parse(data);
        // Delete state after verification (one-time use)
        await redis.del(`oauth:state:${state}`);
        return parsed.provider === expectedProvider;
    } catch {
        return false;
    }
}

// ============================================
// OAUTH AUTHORIZATION URL
// ============================================

/**
 * Generate OAuth authorization URL
 */
export function getOAuthAuthorizationUrl(provider: string, state: string): string {
    const providerConfig = oauthProviders[provider];
    if (!providerConfig) {
        throw new Error(`Unknown OAuth provider: ${provider}`);
    }

    const params = new URLSearchParams({
        client_id: providerConfig.clientId,
        redirect_uri: providerConfig.callbackUrl,
        response_type: 'code',
        scope: providerConfig.scopes.join(' '),
        state,
    });

    // GitHub specific
    if (provider === 'github') {
        params.set('allow_signup', 'true');
    }

    // Microsoft specific
    if (provider === 'microsoft') {
        params.set('response_mode', 'query');
    }

    return `${providerConfig.authUrl}?${params.toString()}`;
}

// ============================================
// TOKEN EXCHANGE
// ============================================

interface OAuthTokens {
    accessToken: string;
    refreshToken?: string;
    expiresIn?: number;
    tokenType: string;
}

/**
 * Exchange authorization code for tokens
 */
export async function exchangeCodeForTokens(
    provider: string,
    code: string
): Promise<OAuthTokens> {
    const providerConfig = oauthProviders[provider];
    if (!providerConfig) {
        throw new Error(`Unknown OAuth provider: ${provider}`);
    }

    const params = new URLSearchParams({
        client_id: providerConfig.clientId,
        client_secret: providerConfig.clientSecret,
        code,
        redirect_uri: providerConfig.callbackUrl,
        grant_type: 'authorization_code',
    });

    const response = await fetch(providerConfig.tokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
        },
        body: params.toString(),
    });

    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Token exchange failed: ${error}`);
    }

    const data = await response.json();

    return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresIn: data.expires_in,
        tokenType: data.token_type,
    };
}

// ============================================
// USER INFO FETCHING
// ============================================

export interface OAuthUserInfo {
    id: string;
    email: string;
    name?: string;
    firstName?: string;
    lastName?: string;
    avatarUrl?: string;
}

/**
 * Fetch user info from OAuth provider
 */
export async function getOAuthUserInfo(
    provider: string,
    accessToken: string
): Promise<OAuthUserInfo> {
    const providerConfig = oauthProviders[provider];
    if (!providerConfig) {
        throw new Error(`Unknown OAuth provider: ${provider}`);
    }

    const response = await fetch(providerConfig.userInfoUrl, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/json',
        },
    });

    if (!response.ok) {
        throw new Error('Failed to fetch user info');
    }

    const data = await response.json();

    // Normalize response based on provider
    switch (provider) {
        case 'google':
            return {
                id: data.id,
                email: data.email,
                name: data.name,
                firstName: data.given_name,
                lastName: data.family_name,
                avatarUrl: data.picture,
            };

        case 'github':
            // GitHub may not return email in user info, need separate call
            let email = data.email;
            if (!email) {
                const emailRes = await fetch('https://api.github.com/user/emails', {
                    headers: {
                        Authorization: `Bearer ${accessToken}`,
                        Accept: 'application/json',
                    },
                });
                if (emailRes.ok) {
                    const emails = await emailRes.json();
                    const primary = emails.find((e: { primary: boolean }) => e.primary);
                    email = primary?.email || emails[0]?.email;
                }
            }
            return {
                id: String(data.id),
                email,
                name: data.name,
                avatarUrl: data.avatar_url,
            };

        case 'microsoft':
            return {
                id: data.id,
                email: data.mail || data.userPrincipalName,
                name: data.displayName,
                firstName: data.givenName,
                lastName: data.surname,
            };

        default:
            throw new Error(`Unknown provider: ${provider}`);
    }
}

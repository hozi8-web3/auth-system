import { Router } from 'express';
import {
    requestMagicLink,
    verifyMagicLinkToken,
    getWebAuthnRegistrationOptions,
    verifyWebAuthnRegistration,
    getWebAuthnAuthenticationOptions,
    verifyWebAuthnAuthentication,
    listPasskeys,
    deletePasskey,
} from '../controllers/passwordless.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import { authLimiter, strictLimiter } from '../middleware/rateLimit.middleware.js';
import { validate } from '../middleware/validate.middleware.js';
import { z } from 'zod';

const router = Router();

// ============================================
// MAGIC LINK ROUTES
// ============================================

// Request magic link
router.post(
    '/magic-link/request',
    strictLimiter,
    validate({
        body: z.object({
            email: z.string().email(),
        }),
    }),
    requestMagicLink
);

// Verify magic link
router.post(
    '/magic-link/verify',
    authLimiter,
    validate({
        body: z.object({
            token: z.string().min(32),
        }),
    }),
    verifyMagicLinkToken
);

// ============================================
// WEBAUTHN/PASSKEY ROUTES
// ============================================

// Get registration options (requires auth - adding new passkey)
router.post(
    '/webauthn/register/options',
    requireAuth,
    authLimiter,
    getWebAuthnRegistrationOptions
);

// Verify registration
router.post(
    '/webauthn/register/verify',
    requireAuth,
    authLimiter,
    validate({
        body: z.object({
            credential: z.object({
                id: z.string(),
                rawId: z.string(),
                response: z.object({
                    clientDataJSON: z.string(),
                    attestationObject: z.string(),
                }),
                type: z.literal('public-key'),
            }),
            deviceName: z.string().max(100).optional(),
        }),
    }),
    verifyWebAuthnRegistration
);

// Get authentication options (for login)
router.post(
    '/webauthn/login/options',
    authLimiter,
    validate({
        body: z.object({
            email: z.string().email().optional(),
        }),
    }),
    getWebAuthnAuthenticationOptions
);

// Verify authentication (login)
router.post(
    '/webauthn/login/verify',
    authLimiter,
    validate({
        body: z.object({
            credential: z.object({
                id: z.string(),
                rawId: z.string(),
                response: z.object({
                    clientDataJSON: z.string(),
                    authenticatorData: z.string(),
                    signature: z.string(),
                    userHandle: z.string().optional(),
                }),
                type: z.literal('public-key'),
            }),
        }),
    }),
    verifyWebAuthnAuthentication
);

// List user's passkeys
router.get(
    '/webauthn/credentials',
    requireAuth,
    listPasskeys
);

// Delete a passkey
router.delete(
    '/webauthn/credentials/:credentialId',
    requireAuth,
    strictLimiter,
    deletePasskey
);

export default router;

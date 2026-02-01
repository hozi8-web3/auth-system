import { Router } from 'express';
import {
    initiateOAuth,
    handleOAuthCallback,
    linkOAuthAccount,
    unlinkOAuthAccount,
    getLinkedAccounts,
} from '../controllers/oauth.controller.js';
import { generalLimiter, authLimiter } from '../middleware/rateLimit.middleware.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = Router();

// ============================================
// OAUTH ROUTES
// ============================================

// Get linked accounts (requires auth) - must be before /:provider
router.get(
    '/accounts',
    requireAuth,
    generalLimiter,
    getLinkedAccounts
);

// Initiate OAuth flow
router.get(
    '/:provider',
    generalLimiter,
    initiateOAuth
);

// OAuth callback
router.get(
    '/:provider/callback',
    generalLimiter,
    handleOAuthCallback
);

// Link OAuth account (requires auth)
router.post(
    '/:provider/link',
    requireAuth,
    generalLimiter,
    linkOAuthAccount
);

// Unlink OAuth account (requires auth)
router.delete(
    '/:provider/unlink',
    requireAuth,
    authLimiter,
    unlinkOAuthAccount
);

export default router;

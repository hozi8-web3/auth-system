import { Router } from 'express';
import {
    createApiKey,
    listApiKeys,
    getApiKey,
    updateApiKey,
    revokeApiKey,
    rotateApiKey,
} from '../controllers/apiKey.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import { generalLimiter, strictLimiter } from '../middleware/rateLimit.middleware.js';
import { validate } from '../middleware/validate.middleware.js';
import { z } from 'zod';

const router = Router();

// All routes require authentication
router.use(requireAuth);

// ============================================
// API KEY ROUTES
// ============================================

// Create API key
router.post(
    '/',
    strictLimiter,
    validate({
        body: z.object({
            name: z.string().min(1).max(100),
            scopes: z.array(z.enum(['read', 'write', 'delete', 'admin'])).optional(),
            expiresInDays: z.number().min(1).max(365).optional(),
        }),
    }),
    createApiKey
);

// List API keys
router.get(
    '/',
    generalLimiter,
    listApiKeys
);

// Get API key details
router.get(
    '/:keyId',
    generalLimiter,
    getApiKey
);

// Update API key
router.patch(
    '/:keyId',
    generalLimiter,
    validate({
        body: z.object({
            name: z.string().min(1).max(100).optional(),
            scopes: z.array(z.enum(['read', 'write', 'delete', 'admin'])).optional(),
            isActive: z.boolean().optional(),
        }),
    }),
    updateApiKey
);

// Revoke API key
router.delete(
    '/:keyId',
    strictLimiter,
    revokeApiKey
);

// Rotate API key
router.post(
    '/:keyId/rotate',
    strictLimiter,
    rotateApiKey
);

export default router;

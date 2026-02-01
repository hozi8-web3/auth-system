import { Router } from 'express';
import {
    listUsers,
    getUserDetails,
    updateUserRole,
    lockUser,
    unlockUser,
    forcePasswordReset,
    getAuditLogs,
    getSystemStats,
} from '../controllers/admin.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import { requireAdmin, requireSuperAdmin, requirePermission } from '../middleware/rbac.middleware.js';
import { strictLimiter } from '../middleware/rateLimit.middleware.js';
import { validate } from '../middleware/validate.middleware.js';
import { z } from 'zod';

const router = Router();

// All admin routes require authentication + admin role
router.use(requireAuth);
router.use(requireAdmin);
router.use(strictLimiter);

// ============================================
// ADMIN ROUTES
// ============================================

// List users
router.get(
    '/users',
    requirePermission('MANAGE_USERS'),
    listUsers
);

// Get user details
router.get(
    '/users/:userId',
    requirePermission('MANAGE_USERS'),
    getUserDetails
);

// Update user role (SUPER_ADMIN only for admin roles)
router.put(
    '/users/:userId/role',
    validate({
        body: z.object({
            role: z.enum(['USER', 'MODERATOR', 'ADMIN', 'SUPER_ADMIN']),
        }),
    }),
    requirePermission('MANAGE_ROLES'),
    updateUserRole
);

// Lock user account
router.post(
    '/users/:userId/lock',
    validate({
        body: z.object({
            durationMinutes: z.number().min(1).max(43200).optional(),
            reason: z.string().max(500).optional(),
        }),
    }),
    requirePermission('MANAGE_USERS'),
    lockUser
);

// Unlock user account
router.post(
    '/users/:userId/unlock',
    requirePermission('MANAGE_USERS'),
    unlockUser
);

// Force password reset
router.post(
    '/users/:userId/reset-password',
    validate({
        body: z.object({
            newPassword: z.string().min(12).max(128),
        }),
    }),
    requireSuperAdmin,
    forcePasswordReset
);

// Get audit logs
router.get(
    '/audit-logs',
    requirePermission('VIEW_AUDIT_LOGS'),
    getAuditLogs
);

// Get system stats
router.get(
    '/stats',
    requirePermission('VIEW_AUDIT_LOGS'),
    getSystemStats
);

export default router;

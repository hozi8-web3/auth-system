import { Request, Response } from 'express';
import { Role } from '@prisma/client';
import prisma from '../config/database.js';
import { assignRole, verifyUserRole } from '../config/roleSignature.js';
import { canAssignRole, canManageUser, isRoleHigher } from '../config/rbac.js';
import { createAuditLog, AuditAction, AuditStatus } from '../services/audit.service.js';
import { hashPassword } from '../utils/password.js';
import { revokeAllSessions } from '../utils/jwt.js';

// ============================================
// SECURE ADMIN CONTROLLER
// ============================================
// All admin endpoints verify role from DATABASE
// Never trust JWT claims for role - always re-verify

// ============================================
// LIST USERS
// ============================================

export async function listUsers(req: Request, res: Response): Promise<void> {
    try {
        const { page = 1, limit = 20, search, role } = req.query;

        const pageNum = Math.max(1, parseInt(page as string, 10) || 1);
        const limitNum = Math.min(100, Math.max(1, parseInt(limit as string, 10) || 20));
        const skip = (pageNum - 1) * limitNum;

        const where: Parameters<typeof prisma.user.findMany>[0]['where'] = {};

        if (search && typeof search === 'string') {
            where.OR = [
                { email: { contains: search, mode: 'insensitive' } },
                { firstName: { contains: search, mode: 'insensitive' } },
                { lastName: { contains: search, mode: 'insensitive' } },
            ];
        }

        if (role && typeof role === 'string') {
            where.role = role as Role;
        }

        const [users, total] = await Promise.all([
            prisma.user.findMany({
                where,
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    lastName: true,
                    role: true,
                    emailVerified: true,
                    twoFactorEnabled: true,
                    lockedUntil: true,
                    lastLoginAt: true,
                    createdAt: true,
                },
                skip,
                take: limitNum,
                orderBy: { createdAt: 'desc' },
            }),
            prisma.user.count({ where }),
        ]);

        res.json({
            success: true,
            data: {
                users,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    total,
                    pages: Math.ceil(total / limitNum),
                },
            },
        });
    } catch (error) {
        console.error('List users error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to list users',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// GET USER DETAILS
// ============================================

export async function getUserDetails(req: Request, res: Response): Promise<void> {
    try {
        const { userId } = req.params;

        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                role: true,
                permissions: true,
                emailVerified: true,
                twoFactorEnabled: true,
                lockedUntil: true,
                failedLoginAttempts: true,
                lastLoginAt: true,
                lastLoginIp: true,
                lastLoginCountry: true,
                trustedCountries: true,
                createdAt: true,
                updatedAt: true,
                sessions: {
                    select: {
                        id: true,
                        userAgent: true,
                        ipAddress: true,
                        country: true,
                        isValid: true,
                        lastUsedAt: true,
                        createdAt: true,
                    },
                    where: { isValid: true },
                    orderBy: { lastUsedAt: 'desc' },
                },
                oauthAccounts: {
                    select: {
                        provider: true,
                        providerEmail: true,
                        createdAt: true,
                    },
                },
                webauthnCredentials: {
                    select: {
                        id: true,
                        deviceName: true,
                        lastUsedAt: true,
                        createdAt: true,
                    },
                },
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
        console.error('Get user details error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get user details',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// UPDATE USER ROLE (SECURE)
// ============================================

export async function updateUserRole(req: Request, res: Response): Promise<void> {
    try {
        const adminId = req.user!.sub;
        const { userId } = req.params;
        const { role: newRole } = req.body as { role: Role };

        // CRITICAL: Verify admin's role from database (not JWT)
        const adminVerification = await verifyUserRole(adminId, req.userRole!);
        if (!adminVerification.valid) {
            await createAuditLog({
                userId: adminId,
                action: AuditAction.SUSPICIOUS_ACTIVITY,
                status: AuditStatus.FAILURE,
                details: {
                    reason: 'Admin role verification failed during role assignment',
                    verificationReason: adminVerification.reason,
                    targetUserId: userId,
                    targetRole: newRole,
                    severity: 'CRITICAL',
                },
                req,
            });

            res.status(403).json({
                success: false,
                error: 'Admin verification failed',
                code: 'ADMIN_VERIFICATION_FAILED',
            });
            return;
        }

        // Check if admin can assign this role
        if (!canAssignRole(adminVerification.actualRole!, newRole)) {
            res.status(403).json({
                success: false,
                error: 'You cannot assign this role',
                code: 'CANNOT_ASSIGN_ROLE',
            });
            return;
        }

        // Get target user
        const targetUser = await prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, role: true, email: true },
        });

        if (!targetUser) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        // Cannot modify user of same or higher role
        if (!isRoleHigher(adminVerification.actualRole!, targetUser.role)) {
            res.status(403).json({
                success: false,
                error: 'Cannot modify user of same or higher role',
                code: 'INSUFFICIENT_ROLE',
            });
            return;
        }

        // Cannot self-promote
        if (adminId === userId) {
            res.status(403).json({
                success: false,
                error: 'Cannot modify own role',
                code: 'SELF_ROLE_CHANGE',
            });
            return;
        }

        // Assign role with cryptographic signature
        await assignRole(userId, newRole, adminId);

        // Audit log
        await createAuditLog({
            userId,
            action: AuditAction.MANAGE_ROLES as unknown as AuditAction,
            status: AuditStatus.SUCCESS,
            details: {
                previousRole: targetUser.role,
                newRole,
                assignedBy: adminId,
                assignerRole: adminVerification.actualRole,
            },
            req,
        });

        res.json({
            success: true,
            message: `User role updated to ${newRole}`,
        });
    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update user role',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// LOCK USER ACCOUNT
// ============================================

export async function lockUser(req: Request, res: Response): Promise<void> {
    try {
        const adminId = req.user!.sub;
        const { userId } = req.params;
        const { durationMinutes = 60, reason } = req.body;

        // Verify target user can be managed
        const targetUser = await prisma.user.findUnique({
            where: { id: userId },
            select: { role: true },
        });

        if (!targetUser) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        if (!isRoleHigher(req.userRole!, targetUser.role)) {
            res.status(403).json({
                success: false,
                error: 'Cannot lock user of same or higher role',
                code: 'INSUFFICIENT_ROLE',
            });
            return;
        }

        const lockedUntil = new Date();
        lockedUntil.setMinutes(lockedUntil.getMinutes() + durationMinutes);

        await prisma.user.update({
            where: { id: userId },
            data: { lockedUntil },
        });

        // Revoke all sessions
        await revokeAllSessions(userId);

        await createAuditLog({
            userId,
            action: AuditAction.ACCOUNT_LOCKED,
            status: AuditStatus.SUCCESS,
            details: {
                lockedBy: adminId,
                duration: durationMinutes,
                reason,
            },
            req,
        });

        res.json({
            success: true,
            message: `User locked until ${lockedUntil.toISOString()}`,
        });
    } catch (error) {
        console.error('Lock user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to lock user',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// UNLOCK USER ACCOUNT
// ============================================

export async function unlockUser(req: Request, res: Response): Promise<void> {
    try {
        const adminId = req.user!.sub;
        const { userId } = req.params;

        await prisma.user.update({
            where: { id: userId },
            data: {
                lockedUntil: null,
                failedLoginAttempts: 0,
            },
        });

        await createAuditLog({
            userId,
            action: AuditAction.ACCOUNT_UNLOCKED,
            status: AuditStatus.SUCCESS,
            details: { unlockedBy: adminId },
            req,
        });

        res.json({
            success: true,
            message: 'User account unlocked',
        });
    } catch (error) {
        console.error('Unlock user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to unlock user',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// FORCE PASSWORD RESET
// ============================================

export async function forcePasswordReset(req: Request, res: Response): Promise<void> {
    try {
        const adminId = req.user!.sub;
        const { userId } = req.params;
        const { newPassword } = req.body;

        // Verify target can be managed
        const targetUser = await prisma.user.findUnique({
            where: { id: userId },
            select: { role: true },
        });

        if (!targetUser) {
            res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
            });
            return;
        }

        if (!isRoleHigher(req.userRole!, targetUser.role)) {
            res.status(403).json({
                success: false,
                error: 'Cannot reset password for user of same or higher role',
                code: 'INSUFFICIENT_ROLE',
            });
            return;
        }

        const passwordHash = await hashPassword(newPassword);

        await prisma.user.update({
            where: { id: userId },
            data: { passwordHash },
        });

        // Revoke all sessions
        await revokeAllSessions(userId);

        await createAuditLog({
            userId,
            action: AuditAction.PASSWORD_RESET,
            status: AuditStatus.SUCCESS,
            details: {
                resetBy: adminId,
                adminAction: true,
            },
            req,
        });

        res.json({
            success: true,
            message: 'Password reset successfully',
        });
    } catch (error) {
        console.error('Force password reset error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to reset password',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// VIEW AUDIT LOGS
// ============================================

export async function getAuditLogs(req: Request, res: Response): Promise<void> {
    try {
        const {
            page = 1,
            limit = 50,
            userId,
            action,
            severity,
            startDate,
            endDate,
        } = req.query;

        const pageNum = Math.max(1, parseInt(page as string, 10) || 1);
        const limitNum = Math.min(100, Math.max(1, parseInt(limit as string, 10) || 50));
        const skip = (pageNum - 1) * limitNum;

        const where: Parameters<typeof prisma.auditLog.findMany>[0]['where'] = {};

        if (userId) where.userId = userId as string;
        if (action) where.action = action as string;
        if (severity) where.severity = severity as string;
        if (startDate || endDate) {
            where.createdAt = {};
            if (startDate) where.createdAt.gte = new Date(startDate as string);
            if (endDate) where.createdAt.lte = new Date(endDate as string);
        }

        const [logs, total] = await Promise.all([
            prisma.auditLog.findMany({
                where,
                include: {
                    user: {
                        select: { email: true, firstName: true, lastName: true },
                    },
                },
                skip,
                take: limitNum,
                orderBy: { createdAt: 'desc' },
            }),
            prisma.auditLog.count({ where }),
        ]);

        res.json({
            success: true,
            data: {
                logs,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    total,
                    pages: Math.ceil(total / limitNum),
                },
            },
        });
    } catch (error) {
        console.error('Get audit logs error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get audit logs',
            code: 'INTERNAL_ERROR',
        });
    }
}

// ============================================
// SYSTEM STATS
// ============================================

export async function getSystemStats(req: Request, res: Response): Promise<void> {
    try {
        const [
            totalUsers,
            verifiedUsers,
            activeUsers24h,
            lockedUsers,
            twoFactorEnabled,
            activeSessions,
            roleDistribution,
        ] = await Promise.all([
            prisma.user.count(),
            prisma.user.count({ where: { emailVerified: true } }),
            prisma.user.count({
                where: { lastLoginAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
            }),
            prisma.user.count({ where: { lockedUntil: { gt: new Date() } } }),
            prisma.user.count({ where: { twoFactorEnabled: true } }),
            prisma.session.count({ where: { isValid: true, expiresAt: { gt: new Date() } } }),
            prisma.user.groupBy({
                by: ['role'],
                _count: { role: true },
            }),
        ]);

        res.json({
            success: true,
            data: {
                users: {
                    total: totalUsers,
                    verified: verifiedUsers,
                    active24h: activeUsers24h,
                    locked: lockedUsers,
                    with2FA: twoFactorEnabled,
                },
                sessions: {
                    active: activeSessions,
                },
                roleDistribution: roleDistribution.reduce(
                    (acc, item) => ({ ...acc, [item.role]: item._count.role }),
                    {}
                ),
            },
        });
    } catch (error) {
        console.error('Get system stats error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get system stats',
            code: 'INTERNAL_ERROR',
        });
    }
}

export default {
    listUsers,
    getUserDetails,
    updateUserRole,
    lockUser,
    unlockUser,
    forcePasswordReset,
    getAuditLogs,
    getSystemStats,
};

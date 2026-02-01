import { Request, Response, NextFunction } from 'express';
import { Role, Permission } from '@prisma/client';
import prisma from '../config/database.js';
import { verifyUserRole } from '../config/roleSignature.js';
import { roleHasPermission, isRoleHigherOrEqual, ROLE_HIERARCHY } from '../config/rbac.js';
import { createAuditLog, AuditAction, AuditStatus } from '../services/audit.service.js';

// ============================================
// EXTEND EXPRESS REQUEST TYPE
// ============================================

declare global {
    namespace Express {
        interface Request {
            userRole?: Role;
            userPermissions?: Permission[];
        }
    }
}

// ============================================
// ROLE MIDDLEWARE
// ============================================

/**
 * Require a minimum role level
 * Uses database verification - NEVER trusts client-provided role
 */
export function requireRole(...allowedRoles: Role[]) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            if (!req.user) {
                res.status(401).json({
                    success: false,
                    error: 'Authentication required',
                    code: 'NOT_AUTHENTICATED',
                });
                return;
            }

            // CRITICAL: Always fetch role from database, never trust JWT claims
            const user = await prisma.user.findUnique({
                where: { id: req.user.sub },
                select: {
                    id: true,
                    role: true,
                    permissions: true,
                    roleSignature: true,
                    roleSignatureExpiry: true,
                },
            });

            if (!user) {
                res.status(401).json({
                    success: false,
                    error: 'User not found',
                    code: 'USER_NOT_FOUND',
                });
                return;
            }

            // Check if user's role is in allowed roles
            const hasAllowedRole = allowedRoles.some((allowedRole) =>
                isRoleHigherOrEqual(user.role, allowedRole)
            );

            if (!hasAllowedRole) {
                // Log unauthorized access attempt
                await createAuditLog({
                    userId: user.id,
                    action: AuditAction.SUSPICIOUS_ACTIVITY,
                    status: AuditStatus.FAILURE,
                    details: {
                        reason: 'Insufficient role',
                        requiredRoles: allowedRoles,
                        actualRole: user.role,
                        endpoint: req.path,
                    },
                    req,
                });

                res.status(403).json({
                    success: false,
                    error: 'Insufficient permissions',
                    code: 'INSUFFICIENT_ROLE',
                });
                return;
            }

            // For ADMIN and SUPER_ADMIN, verify role signature
            if (user.role === 'ADMIN' || user.role === 'SUPER_ADMIN') {
                const verification = await verifyUserRole(user.id, user.role);

                if (!verification.valid) {
                    // CRITICAL: Role signature invalid - potential attack!
                    await createAuditLog({
                        userId: user.id,
                        action: AuditAction.SUSPICIOUS_ACTIVITY,
                        status: AuditStatus.FAILURE,
                        details: {
                            reason: 'Invalid role signature',
                            verificationReason: verification.reason,
                            claimedRole: user.role,
                            endpoint: req.path,
                            severity: 'CRITICAL',
                        },
                        req,
                    });

                    res.status(403).json({
                        success: false,
                        error: 'Role verification failed',
                        code: 'ROLE_VERIFICATION_FAILED',
                    });
                    return;
                }
            }

            // Set verified role on request
            req.userRole = user.role;
            req.userPermissions = user.permissions;

            next();
        } catch (error) {
            console.error('Role verification error:', error);
            res.status(500).json({
                success: false,
                error: 'Role verification failed',
                code: 'INTERNAL_ERROR',
            });
        }
    };
}

/**
 * Require specific permission
 */
export function requirePermission(...requiredPermissions: Permission[]) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            if (!req.user) {
                res.status(401).json({
                    success: false,
                    error: 'Authentication required',
                    code: 'NOT_AUTHENTICATED',
                });
                return;
            }

            const user = await prisma.user.findUnique({
                where: { id: req.user.sub },
                select: {
                    id: true,
                    role: true,
                    permissions: true,
                },
            });

            if (!user) {
                res.status(401).json({
                    success: false,
                    error: 'User not found',
                    code: 'USER_NOT_FOUND',
                });
                return;
            }

            // Check if user has all required permissions
            const hasAllPermissions = requiredPermissions.every((permission) => {
                // Check role-based permissions first
                if (roleHasPermission(user.role, permission)) {
                    return true;
                }
                // Then check user-specific permissions
                return user.permissions.includes(permission);
            });

            if (!hasAllPermissions) {
                await createAuditLog({
                    userId: user.id,
                    action: AuditAction.SUSPICIOUS_ACTIVITY,
                    status: AuditStatus.FAILURE,
                    details: {
                        reason: 'Missing permissions',
                        requiredPermissions,
                        userRole: user.role,
                        userPermissions: user.permissions,
                        endpoint: req.path,
                    },
                    req,
                });

                res.status(403).json({
                    success: false,
                    error: 'Insufficient permissions',
                    code: 'INSUFFICIENT_PERMISSIONS',
                });
                return;
            }

            req.userRole = user.role;
            req.userPermissions = user.permissions;

            next();
        } catch (error) {
            console.error('Permission check error:', error);
            res.status(500).json({
                success: false,
                error: 'Permission check failed',
                code: 'INTERNAL_ERROR',
            });
        }
    };
}

/**
 * Require ADMIN role with enhanced security
 * - Verifies role from database
 * - Verifies cryptographic role signature
 * - Logs all admin access attempts
 */
export const requireAdmin = requireRole('ADMIN', 'SUPER_ADMIN');

/**
 * Require SUPER_ADMIN role
 */
export const requireSuperAdmin = requireRole('SUPER_ADMIN');

/**
 * Check if user can manage target user (role hierarchy)
 */
export async function canManageUser(
    actorId: string,
    targetId: string
): Promise<boolean> {
    const [actor, target] = await Promise.all([
        prisma.user.findUnique({ where: { id: actorId }, select: { role: true } }),
        prisma.user.findUnique({ where: { id: targetId }, select: { role: true } }),
    ]);

    if (!actor || !target) return false;

    // Can only manage users of lower role
    return ROLE_HIERARCHY[actor.role] > ROLE_HIERARCHY[target.role];
}

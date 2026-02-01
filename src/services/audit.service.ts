import prisma from '../config/database.js';
import { Request } from 'express';

// ============================================
// AUDIT LOG ACTIONS
// ============================================

export enum AuditAction {
    // Authentication
    REGISTER = 'REGISTER',
    LOGIN = 'LOGIN',
    LOGIN_FAILED = 'LOGIN_FAILED',
    LOGOUT = 'LOGOUT',
    TOKEN_REFRESH = 'TOKEN_REFRESH',

    // Email verification
    EMAIL_VERIFY_SENT = 'EMAIL_VERIFY_SENT',
    EMAIL_VERIFIED = 'EMAIL_VERIFIED',

    // Password
    PASSWORD_CHANGE = 'PASSWORD_CHANGE',
    PASSWORD_RESET_REQUEST = 'PASSWORD_RESET_REQUEST',
    PASSWORD_RESET = 'PASSWORD_RESET',

    // 2FA
    TWO_FACTOR_SETUP = 'TWO_FACTOR_SETUP',
    TWO_FACTOR_ENABLED = 'TWO_FACTOR_ENABLED',
    TWO_FACTOR_DISABLED = 'TWO_FACTOR_DISABLED',
    TWO_FACTOR_VERIFIED = 'TWO_FACTOR_VERIFIED',
    TWO_FACTOR_FAILED = 'TWO_FACTOR_FAILED',
    BACKUP_CODE_USED = 'BACKUP_CODE_USED',

    // Session
    SESSION_REVOKED = 'SESSION_REVOKED',
    ALL_SESSIONS_REVOKED = 'ALL_SESSIONS_REVOKED',

    // Security
    ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
    ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',
    SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',

    // API Keys
    API_KEY_CREATED = 'API_KEY_CREATED',
    API_KEY_UPDATED = 'API_KEY_UPDATED',
    API_KEY_REVOKED = 'API_KEY_REVOKED',
    API_KEY_ROTATED = 'API_KEY_ROTATED',

    // Admin / Role Management
    MANAGE_ROLES = 'MANAGE_ROLES',
    ROLE_CHANGED = 'ROLE_CHANGED',
}

export enum AuditStatus {
    SUCCESS = 'SUCCESS',
    FAILURE = 'FAILURE',
}

// ============================================
// AUDIT LOGGING
// ============================================

interface AuditLogData {
    userId?: string;
    action: AuditAction;
    status: AuditStatus;
    details?: Record<string, unknown>;
    req?: Request;
}

/**
 * Create an audit log entry
 */
export async function createAuditLog(data: AuditLogData): Promise<void> {
    try {
        await prisma.auditLog.create({
            data: {
                userId: data.userId || null,
                action: data.action,
                status: data.status,
                details: data.details ? JSON.stringify(data.details) : null,
                ipAddress: data.req ? getClientIp(data.req) : null,
                userAgent: data.req?.headers['user-agent'] || null,
            },
        });
    } catch (error) {
        // Log but don't throw - audit logging should never break the main flow
        console.error('Failed to create audit log:', error);
    }
}

/**
 * Get audit logs for a user
 */
export async function getUserAuditLogs(
    userId: string,
    options: {
        limit?: number;
        offset?: number;
        actions?: AuditAction[];
        startDate?: Date;
        endDate?: Date;
    } = {}
): Promise<{
    logs: Awaited<ReturnType<typeof prisma.auditLog.findMany>>;
    total: number;
}> {
    const where: Parameters<typeof prisma.auditLog.findMany>[0]['where'] = {
        userId,
        ...(options.actions && { action: { in: options.actions } }),
        ...(options.startDate || options.endDate
            ? {
                createdAt: {
                    ...(options.startDate && { gte: options.startDate }),
                    ...(options.endDate && { lte: options.endDate }),
                },
            }
            : {}),
    };

    const [logs, total] = await Promise.all([
        prisma.auditLog.findMany({
            where,
            orderBy: { createdAt: 'desc' },
            take: options.limit || 50,
            skip: options.offset || 0,
        }),
        prisma.auditLog.count({ where }),
    ]);

    return { logs, total };
}

// ============================================
// HELPERS
// ============================================

/**
 * Extract client IP from request
 */
function getClientIp(req: Request): string {
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
        const ips = typeof forwardedFor === 'string' ? forwardedFor : forwardedFor[0];
        return ips?.split(',')[0]?.trim() || req.ip || 'unknown';
    }
    return req.ip || 'unknown';
}

/**
 * Clean up old audit logs (keep last N days)
 */
export async function cleanupOldAuditLogs(retentionDays: number = 90): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const result = await prisma.auditLog.deleteMany({
        where: {
            createdAt: { lt: cutoffDate },
        },
    });

    return result.count;
}

export default {
    createAuditLog,
    getUserAuditLogs,
    cleanupOldAuditLogs,
    AuditAction,
    AuditStatus,
};

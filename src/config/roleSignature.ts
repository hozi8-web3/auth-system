import crypto from 'crypto';
import config from './index.js';
import prisma from './database.js';
import { Role } from '@prisma/client';

// ============================================
// ROLE SIGNATURE MANAGEMENT
// ============================================
// This prevents role manipulation through request interception.
// The role signature is a cryptographic proof that a role was
// legitimately assigned by the system.

const ROLE_SIGNATURE_SECRET = process.env.ROLE_SIGNATURE_SECRET || config.jwt.issuer + '-role-secret';
const ROLE_SIGNATURE_VALIDITY_HOURS = 24;

/**
 * Generate a cryptographic signature for a user's role
 * This signature proves the role was legitimately assigned
 */
export function generateRoleSignature(userId: string, role: Role): string {
    const timestamp = Date.now();
    const data = `${userId}:${role}:${timestamp}`;
    const signature = crypto
        .createHmac('sha256', ROLE_SIGNATURE_SECRET)
        .update(data)
        .digest('hex');

    return `${timestamp}:${signature}`;
}

/**
 * Verify a role signature
 */
export function verifyRoleSignature(
    userId: string,
    role: Role,
    signature: string
): boolean {
    try {
        const [timestampStr, sig] = signature.split(':');
        if (!timestampStr || !sig) return false;

        const timestamp = parseInt(timestampStr, 10);
        const data = `${userId}:${role}:${timestamp}`;

        const expectedSig = crypto
            .createHmac('sha256', ROLE_SIGNATURE_SECRET)
            .update(data)
            .digest('hex');

        // Timing-safe comparison
        if (sig.length !== expectedSig.length) return false;
        return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig));
    } catch {
        return false;
    }
}

/**
 * Assign a role to a user with cryptographic signature
 */
export async function assignRole(
    userId: string,
    role: Role,
    assignedBy: string
): Promise<void> {
    const signature = generateRoleSignature(userId, role);
    const expiry = new Date();
    expiry.setHours(expiry.getHours() + ROLE_SIGNATURE_VALIDITY_HOURS);

    await prisma.user.update({
        where: { id: userId },
        data: {
            role,
            roleSignature: signature,
            roleSignatureExpiry: expiry,
            roleAssignedAt: new Date(),
            roleAssignedBy: assignedBy,
        },
    });
}

/**
 * Verify user's role from database (TRIPLE verification)
 * 1. Check role in database (source of truth)
 * 2. Verify role signature is valid
 * 3. Verify signature hasn't expired
 */
export async function verifyUserRole(
    userId: string,
    expectedRole: Role
): Promise<{ valid: boolean; actualRole: Role | null; reason?: string }> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
            role: true,
            roleSignature: true,
            roleSignatureExpiry: true,
        },
    });

    if (!user) {
        return { valid: false, actualRole: null, reason: 'User not found' };
    }

    // 1. Check actual role in database
    if (user.role !== expectedRole) {
        return {
            valid: false,
            actualRole: user.role,
            reason: 'Role mismatch'
        };
    }

    // For USER role, no signature verification needed
    if (expectedRole === 'USER') {
        return { valid: true, actualRole: user.role };
    }

    // 2. For elevated roles, verify signature
    if (!user.roleSignature) {
        return {
            valid: false,
            actualRole: user.role,
            reason: 'Missing role signature'
        };
    }

    // 3. Check signature expiry
    if (user.roleSignatureExpiry && user.roleSignatureExpiry < new Date()) {
        return {
            valid: false,
            actualRole: user.role,
            reason: 'Role signature expired'
        };
    }

    // 4. Verify cryptographic signature
    if (!verifyRoleSignature(userId, expectedRole, user.roleSignature)) {
        return {
            valid: false,
            actualRole: user.role,
            reason: 'Invalid role signature'
        };
    }

    return { valid: true, actualRole: user.role };
}

/**
 * Refresh role signature (called periodically for admins)
 */
export async function refreshRoleSignature(userId: string): Promise<void> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { role: true },
    });

    if (!user || user.role === 'USER') return;

    const signature = generateRoleSignature(userId, user.role);
    const expiry = new Date();
    expiry.setHours(expiry.getHours() + ROLE_SIGNATURE_VALIDITY_HOURS);

    await prisma.user.update({
        where: { id: userId },
        data: {
            roleSignature: signature,
            roleSignatureExpiry: expiry,
        },
    });
}

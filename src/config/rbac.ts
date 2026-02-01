import { Role, Permission } from '@prisma/client';

// ============================================
// ROLE HIERARCHY
// ============================================

export const ROLE_HIERARCHY: Record<Role, number> = {
    USER: 1,
    MODERATOR: 2,
    ADMIN: 3,
    SUPER_ADMIN: 4,
};

// ============================================
// DEFAULT PERMISSIONS PER ROLE
// ============================================

export const DEFAULT_ROLE_PERMISSIONS: Record<Role, Permission[]> = {
    USER: [
        'READ_PROFILE',
        'UPDATE_PROFILE',
        'DELETE_ACCOUNT',
        'READ_CONTENT',
    ],
    MODERATOR: [
        'READ_PROFILE',
        'UPDATE_PROFILE',
        'DELETE_ACCOUNT',
        'READ_CONTENT',
        'CREATE_CONTENT',
        'UPDATE_CONTENT',
        'DELETE_CONTENT',
    ],
    ADMIN: [
        'READ_PROFILE',
        'UPDATE_PROFILE',
        'DELETE_ACCOUNT',
        'READ_CONTENT',
        'CREATE_CONTENT',
        'UPDATE_CONTENT',
        'DELETE_CONTENT',
        'MANAGE_USERS',
        'VIEW_AUDIT_LOGS',
        'MANAGE_API_KEYS',
    ],
    SUPER_ADMIN: [
        'READ_PROFILE',
        'UPDATE_PROFILE',
        'DELETE_ACCOUNT',
        'READ_CONTENT',
        'CREATE_CONTENT',
        'UPDATE_CONTENT',
        'DELETE_CONTENT',
        'MANAGE_USERS',
        'MANAGE_ROLES',
        'VIEW_AUDIT_LOGS',
        'MANAGE_API_KEYS',
        'SYSTEM_SETTINGS',
    ],
};

// ============================================
// PERMISSION CHECKS
// ============================================

/**
 * Check if a role has a specific permission
 */
export function roleHasPermission(role: Role, permission: Permission): boolean {
    const permissions = DEFAULT_ROLE_PERMISSIONS[role];
    return permissions.includes(permission);
}

/**
 * Check if role1 is higher than or equal to role2
 */
export function isRoleHigherOrEqual(role1: Role, role2: Role): boolean {
    return ROLE_HIERARCHY[role1] >= ROLE_HIERARCHY[role2];
}

/**
 * Check if role1 is strictly higher than role2
 */
export function isRoleHigher(role1: Role, role2: Role): boolean {
    return ROLE_HIERARCHY[role1] > ROLE_HIERARCHY[role2];
}

/**
 * Get all permissions for a role (including inherited)
 */
export function getAllPermissionsForRole(role: Role): Permission[] {
    return DEFAULT_ROLE_PERMISSIONS[role];
}

/**
 * Check if user can assign a specific role
 * Only SUPER_ADMIN can assign ADMIN or SUPER_ADMIN
 * ADMIN can assign USER or MODERATOR
 */
export function canAssignRole(assignerRole: Role, targetRole: Role): boolean {
    // SUPER_ADMIN can assign any role
    if (assignerRole === 'SUPER_ADMIN') {
        return true;
    }

    // ADMIN can only assign USER or MODERATOR
    if (assignerRole === 'ADMIN') {
        return targetRole === 'USER' || targetRole === 'MODERATOR';
    }

    // Others cannot assign roles
    return false;
}

/**
 * Check if user can perform admin actions on another user
 */
export function canManageUser(actorRole: Role, targetRole: Role): boolean {
    // Cannot manage users of same or higher role
    return isRoleHigher(actorRole, targetRole);
}

import { Request, Response } from 'express';
import prisma from '../config/database.js';
import { generateSecureToken, sha256 } from '../utils/crypto.js';
import { createAuditLog, AuditAction, AuditStatus } from '../services/audit.service.js';

// ============================================
// API KEY CONTROLLER
// ============================================

const API_KEY_PREFIX = 'ak_';

/**
 * Generate a new API key for the user
 */
export async function createApiKey(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { name, scopes = ['read'], expiresInDays } = req.body;

        // Generate key
        const rawKey = `${API_KEY_PREFIX}${generateSecureToken(32)}`;
        const keyHash = sha256(rawKey);
        const keyPrefix = rawKey.slice(0, 12);

        // Calculate expiry
        let expiresAt: Date | null = null;
        if (expiresInDays) {
            expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + expiresInDays);
        }

        // Create API key
        const apiKey = await prisma.apiKey.create({
            data: {
                userId,
                name,
                keyHash,
                keyPrefix,
                scopes,
                expiresAt,
            },
        });

        await createAuditLog({
            userId,
            action: AuditAction.API_KEY_CREATED as unknown as AuditAction,
            status: AuditStatus.SUCCESS,
            details: { keyId: apiKey.id, name, scopes },
            req,
        });

        // Return the raw key ONLY ONCE - it cannot be retrieved again
        res.status(201).json({
            success: true,
            data: {
                id: apiKey.id,
                name: apiKey.name,
                key: rawKey, // Only shown once!
                keyPrefix: apiKey.keyPrefix,
                scopes: apiKey.scopes,
                expiresAt: apiKey.expiresAt,
                createdAt: apiKey.createdAt,
            },
            warning: 'Save this key now - it will not be shown again!',
        });
    } catch (error) {
        console.error('Create API key error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to create API key',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * List user's API keys
 */
export async function listApiKeys(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;

        const keys = await prisma.apiKey.findMany({
            where: { userId },
            select: {
                id: true,
                name: true,
                keyPrefix: true,
                scopes: true,
                rateLimit: true,
                lastUsedAt: true,
                lastUsedIp: true,
                expiresAt: true,
                isActive: true,
                createdAt: true,
            },
            orderBy: { createdAt: 'desc' },
        });

        res.json({
            success: true,
            data: { keys },
        });
    } catch (error) {
        console.error('List API keys error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to list API keys',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Get API key details
 */
export async function getApiKey(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { keyId } = req.params;

        const key = await prisma.apiKey.findFirst({
            where: { id: keyId, userId },
            select: {
                id: true,
                name: true,
                keyPrefix: true,
                scopes: true,
                permissions: true,
                rateLimit: true,
                lastUsedAt: true,
                lastUsedIp: true,
                expiresAt: true,
                isActive: true,
                createdAt: true,
            },
        });

        if (!key) {
            res.status(404).json({
                success: false,
                error: 'API key not found',
                code: 'KEY_NOT_FOUND',
            });
            return;
        }

        res.json({
            success: true,
            data: { key },
        });
    } catch (error) {
        console.error('Get API key error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get API key',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Update API key
 */
export async function updateApiKey(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { keyId } = req.params;
        const { name, scopes, isActive } = req.body;

        const key = await prisma.apiKey.findFirst({
            where: { id: keyId, userId },
        });

        if (!key) {
            res.status(404).json({
                success: false,
                error: 'API key not found',
                code: 'KEY_NOT_FOUND',
            });
            return;
        }

        const updatedKey = await prisma.apiKey.update({
            where: { id: keyId },
            data: {
                ...(name !== undefined && { name }),
                ...(scopes !== undefined && { scopes }),
                ...(isActive !== undefined && { isActive }),
            },
        });

        await createAuditLog({
            userId,
            action: AuditAction.API_KEY_UPDATED as unknown as AuditAction,
            status: AuditStatus.SUCCESS,
            details: { keyId, changes: { name, scopes, isActive } },
            req,
        });

        res.json({
            success: true,
            data: {
                id: updatedKey.id,
                name: updatedKey.name,
                scopes: updatedKey.scopes,
                isActive: updatedKey.isActive,
            },
        });
    } catch (error) {
        console.error('Update API key error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update API key',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Revoke (delete) an API key
 */
export async function revokeApiKey(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { keyId } = req.params;

        const key = await prisma.apiKey.findFirst({
            where: { id: keyId, userId },
        });

        if (!key) {
            res.status(404).json({
                success: false,
                error: 'API key not found',
                code: 'KEY_NOT_FOUND',
            });
            return;
        }

        await prisma.apiKey.delete({
            where: { id: keyId },
        });

        await createAuditLog({
            userId,
            action: AuditAction.API_KEY_REVOKED as unknown as AuditAction,
            status: AuditStatus.SUCCESS,
            details: { keyId, keyPrefix: key.keyPrefix },
            req,
        });

        res.json({
            success: true,
            message: 'API key revoked successfully',
        });
    } catch (error) {
        console.error('Revoke API key error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to revoke API key',
            code: 'INTERNAL_ERROR',
        });
    }
}

/**
 * Rotate an API key (generate new key, keep same ID)
 */
export async function rotateApiKey(req: Request, res: Response): Promise<void> {
    try {
        const userId = req.user!.sub;
        const { keyId } = req.params;

        const key = await prisma.apiKey.findFirst({
            where: { id: keyId, userId },
        });

        if (!key) {
            res.status(404).json({
                success: false,
                error: 'API key not found',
                code: 'KEY_NOT_FOUND',
            });
            return;
        }

        // Generate new key
        const rawKey = `${API_KEY_PREFIX}${generateSecureToken(32)}`;
        const keyHash = sha256(rawKey);
        const keyPrefix = rawKey.slice(0, 12);

        await prisma.apiKey.update({
            where: { id: keyId },
            data: {
                keyHash,
                keyPrefix,
            },
        });

        await createAuditLog({
            userId,
            action: AuditAction.API_KEY_ROTATED as unknown as AuditAction,
            status: AuditStatus.SUCCESS,
            details: { keyId, oldPrefix: key.keyPrefix, newPrefix: keyPrefix },
            req,
        });

        res.json({
            success: true,
            data: {
                id: keyId,
                key: rawKey,
                keyPrefix,
            },
            warning: 'Save this key now - it will not be shown again!',
        });
    } catch (error) {
        console.error('Rotate API key error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to rotate API key',
            code: 'INTERNAL_ERROR',
        });
    }
}

export default {
    createApiKey,
    listApiKeys,
    getApiKey,
    updateApiKey,
    revokeApiKey,
    rotateApiKey,
};

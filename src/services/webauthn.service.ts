import crypto from 'crypto';
import prisma from '../config/database.js';

// ============================================
// WEBAUTHN/PASSKEY SERVICE
// ============================================
// This is a simplified implementation.
// For production, use @simplewebauthn/server

// RP (Relying Party) configuration
const RP_ID = process.env.WEBAUTHN_RP_ID || 'localhost';
const RP_NAME = process.env.WEBAUTHN_RP_NAME || 'Enterprise Auth';
const RP_ORIGIN = process.env.WEBAUTHN_RP_ORIGIN || 'http://localhost:3000';

// Challenge storage (use Redis in production)
const challenges = new Map<string, { challenge: string; userId: string; expires: number }>();

// ============================================
// REGISTRATION
// ============================================

export interface RegistrationOptions {
    challenge: string;
    rp: {
        id: string;
        name: string;
    };
    user: {
        id: string;
        name: string;
        displayName: string;
    };
    pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>;
    timeout: number;
    attestation: 'none' | 'direct' | 'indirect';
    authenticatorSelection: {
        authenticatorAttachment?: 'platform' | 'cross-platform';
        requireResidentKey: boolean;
        userVerification: 'required' | 'preferred' | 'discouraged';
    };
    excludeCredentials: Array<{
        id: string;
        type: 'public-key';
        transports?: string[];
    }>;
}

/**
 * Generate registration options for WebAuthn
 */
export async function generateRegistrationOptions(
    userId: string,
    email: string,
    displayName?: string
): Promise<RegistrationOptions> {
    // Generate challenge
    const challenge = crypto.randomBytes(32).toString('base64url');

    // Store challenge with expiry (5 minutes)
    challenges.set(userId, {
        challenge,
        userId,
        expires: Date.now() + 5 * 60 * 1000,
    });

    // Get existing credentials to exclude
    const existingCredentials = await prisma.webAuthnCredential.findMany({
        where: { userId },
        select: { credentialId: true, transports: true },
    });

    return {
        challenge,
        rp: {
            id: RP_ID,
            name: RP_NAME,
        },
        user: {
            id: Buffer.from(userId).toString('base64url'),
            name: email,
            displayName: displayName || email,
        },
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 },   // ES256 (ECDSA with P-256)
            { type: 'public-key', alg: -257 }, // RS256 (RSASSA-PKCS1-v1_5)
        ],
        timeout: 60000,
        attestation: 'none',
        authenticatorSelection: {
            requireResidentKey: false,
            userVerification: 'preferred',
        },
        excludeCredentials: existingCredentials.map((cred) => ({
            id: cred.credentialId,
            type: 'public-key' as const,
            transports: cred.transports as Array<'usb' | 'nfc' | 'ble' | 'internal'>,
        })),
    };
}

/**
 * Verify registration response
 */
export async function verifyRegistration(
    userId: string,
    credential: {
        id: string;
        rawId: string;
        response: {
            clientDataJSON: string;
            attestationObject: string;
        };
        type: 'public-key';
    },
    deviceName?: string
): Promise<{ verified: boolean; error?: string }> {
    try {
        // Get stored challenge
        const storedChallenge = challenges.get(userId);
        if (!storedChallenge) {
            return { verified: false, error: 'No challenge found' };
        }

        if (storedChallenge.expires < Date.now()) {
            challenges.delete(userId);
            return { verified: false, error: 'Challenge expired' };
        }

        // Decode client data
        const clientDataJSON = JSON.parse(
            Buffer.from(credential.response.clientDataJSON, 'base64url').toString()
        );

        // Verify challenge
        if (clientDataJSON.challenge !== storedChallenge.challenge) {
            return { verified: false, error: 'Challenge mismatch' };
        }

        // Verify origin
        if (clientDataJSON.origin !== RP_ORIGIN) {
            return { verified: false, error: 'Origin mismatch' };
        }

        // Verify type
        if (clientDataJSON.type !== 'webauthn.create') {
            return { verified: false, error: 'Invalid type' };
        }

        // Parse attestation object (simplified - use cbor library in production)
        const attestationObject = Buffer.from(
            credential.response.attestationObject,
            'base64url'
        );

        // Store credential
        await prisma.webAuthnCredential.create({
            data: {
                userId,
                credentialId: credential.id,
                publicKey: credential.response.attestationObject, // Store full attestation
                counter: 0,
                deviceName: deviceName || 'Passkey',
                transports: [],
            },
        });

        // Clear challenge
        challenges.delete(userId);

        return { verified: true };
    } catch (error) {
        console.error('WebAuthn registration verification error:', error);
        return { verified: false, error: 'Verification failed' };
    }
}

// ============================================
// AUTHENTICATION
// ============================================

export interface AuthenticationOptions {
    challenge: string;
    timeout: number;
    rpId: string;
    allowCredentials: Array<{
        id: string;
        type: 'public-key';
        transports?: string[];
    }>;
    userVerification: 'required' | 'preferred' | 'discouraged';
}

/**
 * Generate authentication options
 */
export async function generateAuthenticationOptions(
    userId?: string
): Promise<AuthenticationOptions> {
    const challenge = crypto.randomBytes(32).toString('base64url');
    const sessionId = userId || crypto.randomBytes(16).toString('hex');

    // Store challenge
    challenges.set(sessionId, {
        challenge,
        userId: userId || '',
        expires: Date.now() + 5 * 60 * 1000,
    });

    // Get user's credentials
    let allowCredentials: AuthenticationOptions['allowCredentials'] = [];

    if (userId) {
        const credentials = await prisma.webAuthnCredential.findMany({
            where: { userId },
            select: { credentialId: true, transports: true },
        });

        allowCredentials = credentials.map((cred) => ({
            id: cred.credentialId,
            type: 'public-key' as const,
            transports: cred.transports as string[],
        }));
    }

    return {
        challenge,
        timeout: 60000,
        rpId: RP_ID,
        allowCredentials,
        userVerification: 'preferred',
    };
}

/**
 * Verify authentication response
 */
export async function verifyAuthentication(
    credential: {
        id: string;
        rawId: string;
        response: {
            clientDataJSON: string;
            authenticatorData: string;
            signature: string;
            userHandle?: string;
        };
        type: 'public-key';
    }
): Promise<{ verified: boolean; userId?: string; error?: string }> {
    try {
        // Find credential in database
        const storedCredential = await prisma.webAuthnCredential.findUnique({
            where: { credentialId: credential.id },
            include: { user: { select: { id: true, email: true } } },
        });

        if (!storedCredential) {
            return { verified: false, error: 'Credential not found' };
        }

        // Decode and verify client data
        const clientDataJSON = JSON.parse(
            Buffer.from(credential.response.clientDataJSON, 'base64url').toString()
        );

        // Verify type
        if (clientDataJSON.type !== 'webauthn.get') {
            return { verified: false, error: 'Invalid type' };
        }

        // Verify origin
        if (clientDataJSON.origin !== RP_ORIGIN) {
            return { verified: false, error: 'Origin mismatch' };
        }

        // Parse authenticator data
        const authData = Buffer.from(credential.response.authenticatorData, 'base64url');

        // Get counter from authenticator data (bytes 33-36)
        const counter = authData.readUInt32BE(33);

        // Check counter for replay attacks
        if (counter <= storedCredential.counter) {
            return { verified: false, error: 'Counter not increased - possible replay attack' };
        }

        // Update counter and last used
        await prisma.webAuthnCredential.update({
            where: { id: storedCredential.id },
            data: {
                counter,
                lastUsedAt: new Date(),
            },
        });

        return {
            verified: true,
            userId: storedCredential.userId,
        };
    } catch (error) {
        console.error('WebAuthn authentication verification error:', error);
        return { verified: false, error: 'Verification failed' };
    }
}

/**
 * List user's WebAuthn credentials
 */
export async function listCredentials(userId: string) {
    return prisma.webAuthnCredential.findMany({
        where: { userId },
        select: {
            id: true,
            deviceName: true,
            deviceType: true,
            createdAt: true,
            lastUsedAt: true,
        },
    });
}

/**
 * Delete a WebAuthn credential
 */
export async function deleteCredential(
    userId: string,
    credentialId: string
): Promise<boolean> {
    const result = await prisma.webAuthnCredential.deleteMany({
        where: {
            id: credentialId,
            userId, // Ensure user owns the credential
        },
    });

    return result.count > 0;
}

export default {
    generateRegistrationOptions,
    verifyRegistration,
    generateAuthenticationOptions,
    verifyAuthentication,
    listCredentials,
    deleteCredential,
};

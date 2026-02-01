import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import config from '../config/index.js';
import { generateSecureToken, encrypt, decrypt, sha256 } from './crypto.js';

// ============================================
// TOTP CONFIGURATION
// ============================================

// Configure otplib for security
authenticator.options = {
    digits: 6,
    step: 30,      // 30-second time window
    window: 1,     // Allow 1 step tolerance
};

// ============================================
// 2FA SETUP
// ============================================

export interface TwoFactorSetup {
    secret: string;          // Encrypted secret to store
    otpauthUrl: string;      // URL for authenticator apps
    qrCodeDataUrl: string;   // Base64 QR code image
    backupCodes: string[];   // Plain backup codes (show once)
    backupCodesHashed: string[]; // Hashed codes to store
}

/**
 * Generate 2FA setup data
 */
export async function generateTwoFactorSetup(
    email: string,
    encryptionKey: string
): Promise<TwoFactorSetup> {
    // Generate secret
    const secret = authenticator.generateSecret(32); // 256-bit secret

    // Create OTPAuth URL for authenticator apps
    const otpauthUrl = authenticator.keyuri(email, config.twoFactor.issuer, secret);

    // Generate QR code
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl, {
        errorCorrectionLevel: 'M',
        type: 'image/png',
        margin: 2,
        width: 256,
    });

    // Generate backup codes
    const backupCodes: string[] = [];
    const backupCodesHashed: string[] = [];

    for (let i = 0; i < config.twoFactor.backupCodesCount; i++) {
        // Generate 8-character alphanumeric code
        const code = generateSecureToken(4).toUpperCase().slice(0, 8);
        backupCodes.push(code);
        backupCodesHashed.push(sha256(code));
    }

    // Encrypt secret for storage
    const encryptedSecret = encrypt(secret, encryptionKey);

    return {
        secret: encryptedSecret,
        otpauthUrl,
        qrCodeDataUrl,
        backupCodes,
        backupCodesHashed,
    };
}

// ============================================
// 2FA VERIFICATION
// ============================================

/**
 * Verify a TOTP code
 */
export function verifyTotpCode(
    code: string,
    encryptedSecret: string,
    encryptionKey: string
): boolean {
    try {
        const secret = decrypt(encryptedSecret, encryptionKey);
        return authenticator.verify({ token: code, secret });
    } catch {
        return false;
    }
}

/**
 * Verify a backup code and mark it as used
 * Returns the remaining hashed backup codes if successful
 */
export function verifyBackupCode(
    code: string,
    hashedCodes: string[]
): { valid: boolean; remainingCodes: string[] } {
    const codeHash = sha256(code.toUpperCase().replace(/\s/g, ''));
    const index = hashedCodes.findIndex((hash) => hash === codeHash);

    if (index === -1) {
        return { valid: false, remainingCodes: hashedCodes };
    }

    // Remove used code
    const remainingCodes = [...hashedCodes];
    remainingCodes.splice(index, 1);

    return { valid: true, remainingCodes };
}

/**
 * Verify 2FA (tries TOTP first, then backup code)
 */
export function verifyTwoFactor(
    code: string,
    encryptedSecret: string,
    hashedBackupCodes: string[],
    encryptionKey: string
): { valid: boolean; usedBackupCode: boolean; remainingBackupCodes: string[] } {
    // Try TOTP first
    if (verifyTotpCode(code, encryptedSecret, encryptionKey)) {
        return {
            valid: true,
            usedBackupCode: false,
            remainingBackupCodes: hashedBackupCodes,
        };
    }

    // Try backup code
    const backupResult = verifyBackupCode(code, hashedBackupCodes);
    return {
        valid: backupResult.valid,
        usedBackupCode: backupResult.valid,
        remainingBackupCodes: backupResult.remainingCodes,
    };
}

// ============================================
// HELPERS
// ============================================

/**
 * Format backup codes for display (groups of 4)
 */
export function formatBackupCodes(codes: string[]): string[] {
    return codes.map((code) => {
        return `${code.slice(0, 4)}-${code.slice(4)}`;
    });
}

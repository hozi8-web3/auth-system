import prisma from '../config/database.js';
import config from '../config/index.js';
import { generateSecureToken, sha256 } from '../utils/crypto.js';
import { sendEmail } from './email.service.js';

// ============================================
// MAGIC LINK (PASSWORDLESS) AUTHENTICATION
// ============================================

const MAGIC_LINK_EXPIRY_MINUTES = 15;

/**
 * Generate and send magic link for passwordless login
 */
export async function sendMagicLink(email: string): Promise<void> {
    const token = generateSecureToken(32);
    const tokenHash = sha256(token);
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + MAGIC_LINK_EXPIRY_MINUTES);

    // Find or create user
    let user = await prisma.user.findUnique({
        where: { email },
    });

    if (!user) {
        // Create new user for magic link
        user = await prisma.user.create({
            data: {
                email,
                emailVerified: true, // Magic link verifies email
            },
        });
    }

    // Store magic link token
    await prisma.user.update({
        where: { id: user.id },
        data: {
            magicLinkToken: tokenHash,
            magicLinkExpires: expiresAt,
        },
    });

    // Generate login URL
    const magicLinkUrl = `${config.frontendUrl}/auth/magic-link?token=${token}`;

    // Send email
    await sendMagicLinkEmail(email, magicLinkUrl, user.firstName || undefined);
}

/**
 * Verify magic link token
 */
export async function verifyMagicLink(token: string): Promise<{
    valid: boolean;
    userId?: string;
    email?: string;
    error?: string;
}> {
    const tokenHash = sha256(token);

    const user = await prisma.user.findFirst({
        where: {
            magicLinkToken: tokenHash,
            magicLinkExpires: { gt: new Date() },
        },
    });

    if (!user) {
        return { valid: false, error: 'Invalid or expired magic link' };
    }

    // Clear magic link token (one-time use)
    await prisma.user.update({
        where: { id: user.id },
        data: {
            magicLinkToken: null,
            magicLinkExpires: null,
            emailVerified: true, // Magic link also verifies email
        },
    });

    return {
        valid: true,
        userId: user.id,
        email: user.email,
    };
}

/**
 * Send magic link email
 */
async function sendMagicLinkEmail(
    email: string,
    magicLinkUrl: string,
    firstName?: string
): Promise<void> {
    const name = firstName || 'there';

    await sendEmail({
        to: email,
        subject: 'Your Magic Login Link',
        html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
          .button { display: inline-block; background: #10b981; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
          .warning { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔮 Magic Login</h1>
          </div>
          <div class="content">
            <p>Hi ${name},</p>
            <p>Click the button below to instantly log in - no password needed!</p>
            <p style="text-align: center;">
              <a href="${magicLinkUrl}" class="button">Log In Now</a>
            </p>
            <div class="warning">
              <strong>⚠️ This link expires in ${MAGIC_LINK_EXPIRY_MINUTES} minutes</strong><br>
              If you didn't request this link, you can safely ignore this email.
            </div>
            <p>Or copy and paste this link:</p>
            <p style="word-break: break-all; background: #e5e7eb; padding: 10px; border-radius: 4px; font-size: 12px;">${magicLinkUrl}</p>
          </div>
          <div class="footer">
            <p>This is an automated message from ${config.email.fromName}</p>
          </div>
        </div>
      </body>
      </html>
    `,
    });
}

export default {
    sendMagicLink,
    verifyMagicLink,
};

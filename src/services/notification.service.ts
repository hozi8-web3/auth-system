import prisma from '../config/database.js';
import config from '../config/index.js';
import { sendEmail } from './email.service.js';

// ============================================
// LOGIN NOTIFICATION SERVICE
// ============================================

export type NotificationType =
    | 'NEW_DEVICE'
    | 'NEW_COUNTRY'
    | 'SUSPICIOUS_LOGIN'
    | 'PASSWORD_CHANGED'
    | 'TWO_FACTOR_CHANGE'
    | 'SESSIONS_REVOKED';

interface NotificationContext {
    ipAddress?: string;
    country?: string;
    city?: string;
    device?: string;
    userAgent?: string;
}

/**
 * Create and send a login notification
 */
export async function sendLoginNotification(
    userId: string,
    type: NotificationType,
    context: NotificationContext
): Promise<void> {
    // Get user preferences
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
            email: true,
            firstName: true,
            emailNotificationsEnabled: true,
            smsNotificationsEnabled: true,
            phoneNumber: true,
            pushTokens: true,
        },
    });

    if (!user) return;

    const message = getNotificationMessage(type, context);

    // Store notification in database
    await prisma.loginNotification.create({
        data: {
            userId,
            type,
            message,
            ipAddress: context.ipAddress,
            country: context.country,
            device: context.device,
        },
    });

    // Send notifications based on user preferences
    const promises: Promise<void>[] = [];

    // Email notification
    if (user.emailNotificationsEnabled) {
        promises.push(
            sendEmailNotification(user.email, type, message, context, user.firstName || undefined)
        );
    }

    // SMS notification (for critical events)
    if (user.smsNotificationsEnabled && user.phoneNumber && isCriticalNotification(type)) {
        promises.push(sendSmsNotification(user.phoneNumber, message));
    }

    // Push notification
    if (user.pushTokens.length > 0) {
        promises.push(sendPushNotification(user.pushTokens, type, message));
    }

    await Promise.allSettled(promises);
}

/**
 * Get notification message based on type
 */
function getNotificationMessage(type: NotificationType, context: NotificationContext): string {
    const location = context.country
        ? `${context.city || ''}, ${context.country}`.trim().replace(/^,\s*/, '')
        : 'Unknown location';

    switch (type) {
        case 'NEW_DEVICE':
            return `New device login detected from ${location}`;
        case 'NEW_COUNTRY':
            return `Login from new country: ${context.country || 'Unknown'}`;
        case 'SUSPICIOUS_LOGIN':
            return `Suspicious login attempt detected from ${location}`;
        case 'PASSWORD_CHANGED':
            return 'Your password was changed';
        case 'TWO_FACTOR_CHANGE':
            return 'Your two-factor authentication settings were changed';
        case 'SESSIONS_REVOKED':
            return 'All active sessions have been revoked';
        default:
            return 'Security notification';
    }
}

/**
 * Check if notification type is critical (warrants SMS)
 */
function isCriticalNotification(type: NotificationType): boolean {
    return ['NEW_COUNTRY', 'SUSPICIOUS_LOGIN', 'SESSIONS_REVOKED'].includes(type);
}

/**
 * Send email notification
 */
async function sendEmailNotification(
    email: string,
    type: NotificationType,
    message: string,
    context: NotificationContext,
    firstName?: string
): Promise<void> {
    const name = firstName || 'there';
    const severityColors: Record<string, string> = {
        NEW_DEVICE: '#3b82f6',
        NEW_COUNTRY: '#f59e0b',
        SUSPICIOUS_LOGIN: '#ef4444',
        PASSWORD_CHANGED: '#10b981',
        TWO_FACTOR_CHANGE: '#8b5cf6',
        SESSIONS_REVOKED: '#ef4444',
    };

    const color = severityColors[type] || '#6b7280';

    await sendEmail({
        to: email,
        subject: `🔔 Security Alert: ${message}`,
        html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: ${color}; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
          .details { background: #e5e7eb; padding: 15px; border-radius: 6px; margin: 20px 0; }
          .warning { background: #fee2e2; border-left: 4px solid #ef4444; padding: 12px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔒 Security Alert</h1>
          </div>
          <div class="content">
            <p>Hi ${name},</p>
            <p><strong>${message}</strong></p>
            <div class="details">
              <p><strong>Time:</strong> ${new Date().toISOString()}</p>
              ${context.ipAddress ? `<p><strong>IP Address:</strong> ${context.ipAddress}</p>` : ''}
              ${context.country ? `<p><strong>Location:</strong> ${context.city ? context.city + ', ' : ''}${context.country}</p>` : ''}
              ${context.device || context.userAgent ? `<p><strong>Device:</strong> ${context.device || context.userAgent}</p>` : ''}
            </div>
            ${type === 'SUSPICIOUS_LOGIN' || type === 'NEW_COUNTRY' ? `
            <div class="warning">
              <strong>⚠️ If this wasn't you:</strong>
              <ol>
                <li>Change your password immediately</li>
                <li>Enable two-factor authentication</li>
                <li>Review your active sessions</li>
              </ol>
            </div>
            ` : ''}
            <p>If this was you, no action is needed.</p>
          </div>
          <div class="footer">
            <p>This is an automated security alert from ${config.email.fromName}</p>
          </div>
        </div>
      </body>
      </html>
    `,
    });
}

/**
 * Send SMS notification (placeholder - integrate with Twilio/AWS SNS)
 */
async function sendSmsNotification(
    phoneNumber: string,
    message: string
): Promise<void> {
    // TODO: Integrate with SMS provider (Twilio, AWS SNS, etc.)
    console.log(`[SMS] To: ${phoneNumber}, Message: ${message}`);

    // Example Twilio integration:
    // const twilio = require('twilio')(accountSid, authToken);
    // await twilio.messages.create({
    //   body: message,
    //   from: process.env.TWILIO_PHONE_NUMBER,
    //   to: phoneNumber,
    // });
}

/**
 * Send push notification (placeholder - integrate with Firebase/OneSignal)
 */
async function sendPushNotification(
    tokens: string[],
    type: NotificationType,
    message: string
): Promise<void> {
    // TODO: Integrate with push notification provider (Firebase, OneSignal)
    console.log(`[PUSH] To: ${tokens.length} devices, Type: ${type}, Message: ${message}`);

    // Example Firebase integration:
    // const admin = require('firebase-admin');
    // await admin.messaging().sendMulticast({
    //   tokens,
    //   notification: { title: 'Security Alert', body: message },
    //   data: { type },
    // });
}

export default {
    sendLoginNotification,
};

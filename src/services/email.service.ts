import nodemailer from 'nodemailer';
import config from '../config/index.js';

// ============================================
// EMAIL TRANSPORTER
// ============================================

let transporter: nodemailer.Transporter | null = null;

function getTransporter(): nodemailer.Transporter {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.email.host,
      port: config.email.port,
      secure: config.email.secure,
      auth: {
        user: config.email.user,
        pass: config.email.password,
      },
    });
  }
  return transporter;
}

// ============================================
// EMAIL TEMPLATES
// ============================================

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export async function sendEmail(options: EmailOptions): Promise<void> {
  const transport = getTransporter();

  await transport.sendMail({
    from: `"${config.email.fromName}" <${config.email.fromEmail}>`,
    to: options.to,
    subject: options.subject,
    html: options.html,
    text: options.text || options.html.replace(/<[^>]*>/g, ''),
  });
}

// ============================================
// EMAIL FUNCTIONS
// ============================================

/**
 * Send email verification email
 */
export async function sendVerificationEmail(
  email: string,
  token: string,
  firstName?: string
): Promise<void> {
  const verifyUrl = `${config.apiBaseUrl}/api/${config.apiVersion}/auth/verify-email?token=${token}`;
  const name = firstName || 'there';

  await sendEmail({
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
          .button { display: inline-block; background: #667eea; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
          .button:hover { background: #5a67d8; }
          .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 14px; }
          .warning { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Email Verification</h1>
          </div>
          <div class="content">
            <p>Hi ${name},</p>
            <p>Thank you for registering! Please verify your email address by clicking the button below:</p>
            <p style="text-align: center;">
              <a href="${verifyUrl}" class="button">Verify Email Address</a>
            </p>
            <div class="warning">
              <strong>⚠️ Security Notice:</strong> This link expires in ${config.email.verificationExpiryHours} hours. If you didn't create an account, please ignore this email.
            </div>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #e5e7eb; padding: 10px; border-radius: 4px; font-size: 12px;">${verifyUrl}</p>
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

/**
 * Send password reset email
 */
export async function sendPasswordResetEmail(
  email: string,
  token: string,
  firstName?: string
): Promise<void> {
  const resetUrl = `${config.frontendUrl}/reset-password?token=${token}`;
  const name = firstName || 'there';

  await sendEmail({
    to: email,
    subject: 'Reset Your Password',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
          .button { display: inline-block; background: #ef4444; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 14px; }
          .warning { background: #fee2e2; border-left: 4px solid #ef4444; padding: 12px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Password Reset</h1>
          </div>
          <div class="content">
            <p>Hi ${name},</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </p>
            <div class="warning">
              <strong>⚠️ Security Warning:</strong>
              <ul>
                <li>This link expires in ${config.email.passwordResetExpiryHours} hour(s)</li>
                <li>If you didn't request this, please secure your account immediately</li>
                <li>Never share this link with anyone</li>
              </ul>
            </div>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #e5e7eb; padding: 10px; border-radius: 4px; font-size: 12px;">${resetUrl}</p>
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

/**
 * Send security alert email
 */
export async function sendSecurityAlertEmail(
  email: string,
  alertType: 'new_login' | 'password_changed' | 'two_factor_enabled' | 'two_factor_disabled' | 'sessions_revoked',
  details: { ipAddress?: string; userAgent?: string; location?: string }
): Promise<void> {
  const alertMessages = {
    new_login: {
      title: 'New Login Detected',
      message: 'A new login was detected on your account.',
      color: '#3b82f6',
    },
    password_changed: {
      title: 'Password Changed',
      message: 'Your password was successfully changed.',
      color: '#10b981',
    },
    two_factor_enabled: {
      title: '2FA Enabled',
      message: 'Two-factor authentication has been enabled on your account.',
      color: '#10b981',
    },
    two_factor_disabled: {
      title: '2FA Disabled',
      message: 'Two-factor authentication has been disabled on your account.',
      color: '#f59e0b',
    },
    sessions_revoked: {
      title: 'All Sessions Revoked',
      message: 'All active sessions have been logged out.',
      color: '#ef4444',
    },
  };

  const alert = alertMessages[alertType];

  await sendEmail({
    to: email,
    subject: `Security Alert: ${alert.title}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: ${alert.color}; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
          .details { background: #e5e7eb; padding: 15px; border-radius: 6px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔒 ${alert.title}</h1>
          </div>
          <div class="content">
            <p>${alert.message}</p>
            <div class="details">
              <p><strong>Time:</strong> ${new Date().toISOString()}</p>
              ${details.ipAddress ? `<p><strong>IP Address:</strong> ${details.ipAddress}</p>` : ''}
              ${details.userAgent ? `<p><strong>Device:</strong> ${details.userAgent}</p>` : ''}
            </div>
            <p>If this wasn't you, please secure your account immediately by changing your password and enabling two-factor authentication.</p>
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

export default {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendSecurityAlertEmail,
};

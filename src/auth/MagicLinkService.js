/**
 * Magic Link Authentication Service
 * Handles passwordless authentication via email links
 */

const nodemailer = require('nodemailer');
const config = require('../config');
const { UserModel, TokenModel, MagicLinkModel } = require('../models/User');
const BasicAuthService = require('./BasicAuthService');

class MagicLinkService {
  static transporter = null;

  /**
   * Initialize email transporter
   */
  static initialize() {
    if (!config.email.user || !config.email.pass) {
      console.warn('Email credentials not configured. Magic link service will not work.');
      return;
    }

    this.transporter = nodemailer.createTransport({
      host: config.email.host,
      port: config.email.port,
      secure: config.email.secure,
      auth: {
        user: config.email.user,
        pass: config.email.pass,
      },
    });
  }

  /**
   * Send magic link to user's email
   * @param {string} email - User email
   * @returns {Object} Result with token (for testing) or error
   */
  static async sendMagicLink(email) {
    // Create or find user
    let user = UserModel.findByEmail(email);
    
    if (!user) {
      // Create user with magic link provider
      user = await UserModel.create({
        email,
        name: email.split('@')[0],
        provider: 'magiclink',
      });
    }

    // Generate magic link token
    const token = MagicLinkModel.create(email);
    const magicLinkUrl = `${config.magicLink.baseUrl}/auth/magic-link/verify?token=${token}`;

    // Send email if transporter is configured
    if (this.transporter) {
      try {
        await this.transporter.sendMail({
          from: config.email.from,
          to: email,
          subject: 'Your Magic Login Link',
          html: `
            <h1>Login to ${config.twoFactor.issuer}</h1>
            <p>Click the link below to log in to your account:</p>
            <a href="${magicLinkUrl}" style="
              display: inline-block;
              padding: 12px 24px;
              background-color: #4F46E5;
              color: white;
              text-decoration: none;
              border-radius: 6px;
              margin: 16px 0;
            ">Log In</a>
            <p>This link will expire in ${config.magicLink.expiry / 60000} minutes.</p>
            <p>If you didn't request this link, you can safely ignore this email.</p>
            <hr>
            <p style="color: #666; font-size: 12px;">
              If the button doesn't work, copy and paste this URL into your browser:<br>
              ${magicLinkUrl}
            </p>
          `,
          text: `
            Login to ${config.twoFactor.issuer}
            
            Click the link below to log in to your account:
            ${magicLinkUrl}
            
            This link will expire in ${config.magicLink.expiry / 60000} minutes.
            
            If you didn't request this link, you can safely ignore this email.
          `,
        });

        return { success: true, message: 'Magic link sent to email' };
      } catch (error) {
        console.error('Failed to send magic link email:', error);
        return { success: false, error: 'Failed to send email' };
      }
    }

    // Return token for testing/development
    return {
      success: true,
      message: 'Magic link generated (email not configured)',
      token, // Only for testing
      magicLinkUrl, // Only for testing
    };
  }

  /**
   * Verify magic link and authenticate user
   * @param {string} token - Magic link token
   * @returns {Object|null} User and tokens or null
   */
  static async verifyMagicLink(token) {
    const linkData = MagicLinkModel.validate(token, config.magicLink.expiry);
    
    if (!linkData) {
      return null;
    }

    // Mark link as used
    MagicLinkModel.markUsed(token);

    // Find user by email
    const user = UserModel.findByEmail(linkData.email);
    if (!user) {
      return null;
    }

    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      const tempToken = BasicAuthService.generateTempToken(user);
      return {
        user: UserModel.sanitize(user),
        requiresTwoFactor: true,
        tempToken,
      };
    }

    // Generate tokens
    const tokens = BasicAuthService.generateTokens(user);
    TokenModel.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: UserModel.sanitize(user),
      requiresTwoFactor: false,
      ...tokens,
    };
  }

  /**
   * Check if email service is configured
   * @returns {boolean} Is configured
   */
  static isConfigured() {
    return this.transporter !== null;
  }
}

module.exports = MagicLinkService;

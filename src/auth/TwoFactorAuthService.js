/**
 * Two-Factor Authentication Service
 * Handles TOTP-based 2FA
 */

const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { UserModel, TokenModel } = require('../models/User');
const BasicAuthService = require('./BasicAuthService');
const config = require('../config');

class TwoFactorAuthService {
  /**
   * Generate 2FA secret and QR code for user
   * @param {string} userId - User ID
   * @returns {Object} Secret and QR code data URL
   */
  static async generateSecret(userId) {
    const user = UserModel.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(
      user.email,
      config.twoFactor.issuer,
      secret,
    );

    const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

    // Store secret temporarily (user must verify before enabling)
    return {
      secret,
      qrCode: qrCodeDataUrl,
      otpauth,
    };
  }

  /**
   * Verify TOTP and enable 2FA
   * @param {string} userId - User ID
   * @param {string} secret - TOTP secret
   * @param {string} token - TOTP token to verify
   * @returns {boolean} Success
   */
  static verifyAndEnable(userId, secret, token) {
    const isValid = authenticator.verify({
      token,
      secret,
    });

    if (!isValid) {
      return false;
    }

    // Enable 2FA with verified secret
    UserModel.enable2FA(userId, secret);
    return true;
  }

  /**
   * Verify TOTP token for login
   * @param {string} tempToken - Temporary token from initial login
   * @param {string} totpToken - TOTP token
   * @returns {Object|null} Tokens or null
   */
  static verifyLogin(tempToken, totpToken) {
    const userId = BasicAuthService.verifyTempToken(tempToken);
    if (!userId) {
      return null;
    }

    const user = UserModel.findById(userId);
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      return null;
    }

    const isValid = authenticator.verify({
      token: totpToken,
      secret: user.twoFactorSecret,
    });

    if (!isValid) {
      return null;
    }

    // Generate full tokens
    const tokens = BasicAuthService.generateTokens(user);
    TokenModel.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: UserModel.sanitize(user),
      ...tokens,
    };
  }

  /**
   * Disable 2FA for user
   * @param {string} userId - User ID
   * @param {string} totpToken - Current TOTP token for verification
   * @returns {boolean} Success
   */
  static disable(userId, totpToken) {
    const user = UserModel.findById(userId);
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      return false;
    }

    const isValid = authenticator.verify({
      token: totpToken,
      secret: user.twoFactorSecret,
    });

    if (!isValid) {
      return false;
    }

    UserModel.disable2FA(userId);
    return true;
  }

  /**
   * Generate backup codes for 2FA recovery
   * @param {number} count - Number of backup codes to generate
   * @returns {string[]} Backup codes
   */
  static generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      // Generate 8-character alphanumeric code
      const code = authenticator.generateSecret().substring(0, 8).toUpperCase();
      codes.push(code);
    }
    return codes;
  }
}

module.exports = TwoFactorAuthService;

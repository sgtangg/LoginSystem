/**
 * Basic Authentication Service
 * Handles username/password authentication
 */

const { UserModel, TokenModel } = require('../models/User');
const jwt = require('jsonwebtoken');
const config = require('../config');

class BasicAuthService {
  /**
   * Register a new user
   * @param {Object} userData - User registration data
   * @returns {Object} Created user and tokens
   */
  static async register({ email, password, name }) {
    const user = await UserModel.create({
      email,
      password,
      name,
      provider: 'local',
    });

    const tokens = this.generateTokens(user);
    TokenModel.storeRefreshToken(user.id, tokens.refreshToken);

    return { user, ...tokens };
  }

  /**
   * Login with email and password
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Object} User and tokens or null
   */
  static async login(email, password) {
    const user = UserModel.findByEmail(email);
    if (!user) {
      return null;
    }

    const isValid = await UserModel.validatePassword(user, password);
    if (!isValid) {
      return null;
    }

    // If 2FA is enabled, return partial auth
    if (user.twoFactorEnabled) {
      const tempToken = this.generateTempToken(user);
      return {
        user: UserModel.sanitize(user),
        requiresTwoFactor: true,
        tempToken,
      };
    }

    const tokens = this.generateTokens(user);
    TokenModel.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: UserModel.sanitize(user),
      requiresTwoFactor: false,
      ...tokens,
    };
  }

  /**
   * Logout user
   * @param {string} userId - User ID
   * @param {string} refreshToken - Refresh token to revoke
   */
  static logout(userId, refreshToken) {
    TokenModel.revokeRefreshToken(userId, refreshToken);
  }

  /**
   * Logout from all devices
   * @param {string} userId - User ID
   */
  static logoutAll(userId) {
    TokenModel.revokeAllRefreshTokens(userId);
  }

  /**
   * Refresh access token
   * @param {string} refreshToken - Refresh token
   * @returns {Object} New tokens or null
   */
  static async refreshAccessToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, config.jwt.secret);
      const userId = decoded.userId;

      if (!TokenModel.validateRefreshToken(userId, refreshToken)) {
        return null;
      }

      const user = UserModel.findById(userId);
      if (!user) {
        return null;
      }

      // Revoke old refresh token and generate new ones
      TokenModel.revokeRefreshToken(userId, refreshToken);
      const tokens = this.generateTokens(user);
      TokenModel.storeRefreshToken(userId, tokens.refreshToken);

      return tokens;
    } catch (error) {
      return null;
    }
  }

  /**
   * Generate access and refresh tokens
   * @param {Object} user - User object
   * @returns {Object} Access and refresh tokens
   */
  static generateTokens(user) {
    const accessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        type: 'access',
      },
      config.jwt.secret,
      { expiresIn: config.jwt.accessTokenExpiry },
    );

    const refreshToken = jwt.sign(
      {
        userId: user.id,
        type: 'refresh',
      },
      config.jwt.secret,
      { expiresIn: config.jwt.refreshTokenExpiry },
    );

    return { accessToken, refreshToken };
  }

  /**
   * Generate temporary token for 2FA verification
   * @param {Object} user - User object
   * @returns {string} Temporary token
   */
  static generateTempToken(user) {
    return jwt.sign(
      {
        userId: user.id,
        type: 'temp_2fa',
      },
      config.jwt.secret,
      { expiresIn: '5m' },
    );
  }

  /**
   * Verify temporary 2FA token and return user ID
   * @param {string} token - Temporary token
   * @returns {string|null} User ID or null
   */
  static verifyTempToken(token) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      if (decoded.type !== 'temp_2fa') {
        return null;
      }
      return decoded.userId;
    } catch (error) {
      return null;
    }
  }
}

module.exports = BasicAuthService;

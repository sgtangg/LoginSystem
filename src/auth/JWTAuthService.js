/**
 * JWT Authentication Service
 * Handles JWT token verification and management
 */

const jwt = require('jsonwebtoken');
const config = require('../config');
const { UserModel } = require('../models/User');

class JWTAuthService {
  /**
   * Verify access token
   * @param {string} token - Access token
   * @returns {Object|null} Decoded token payload or null
   */
  static verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      if (decoded.type !== 'access') {
        return null;
      }
      return decoded;
    } catch (error) {
      return null;
    }
  }

  /**
   * Verify refresh token
   * @param {string} token - Refresh token
   * @returns {Object|null} Decoded token payload or null
   */
  static verifyRefreshToken(token) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      if (decoded.type !== 'refresh') {
        return null;
      }
      return decoded;
    } catch (error) {
      return null;
    }
  }

  /**
   * Extract token from Authorization header
   * @param {string} authHeader - Authorization header
   * @returns {string|null} Token or null
   */
  static extractTokenFromHeader(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7);
  }

  /**
   * Decode token without verification (for debugging)
   * @param {string} token - Token to decode
   * @returns {Object|null} Decoded payload or null
   */
  static decodeToken(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      return null;
    }
  }

  /**
   * Check if token is expired
   * @param {string} token - Token to check
   * @returns {boolean} Is expired
   */
  static isTokenExpired(token) {
    const decoded = this.decodeToken(token);
    if (!decoded || !decoded.exp) {
      return true;
    }
    return Date.now() >= decoded.exp * 1000;
  }

  /**
   * Get user from token
   * @param {string} token - Access token
   * @returns {Object|null} User or null
   */
  static getUserFromToken(token) {
    const decoded = this.verifyAccessToken(token);
    if (!decoded) {
      return null;
    }
    return UserModel.findById(decoded.userId);
  }
}

module.exports = JWTAuthService;

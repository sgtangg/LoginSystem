/**
 * Simple In-Memory User Store
 * In production, this would be replaced with a proper database
 */

const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// In-memory storage (replace with database in production)
const users = new Map();
const refreshTokens = new Map();
const magicLinks = new Map();

class UserModel {
  /**
   * Create a new user
   * @param {Object} userData - User data
   * @returns {Object} Created user
   */
  static async create({ email, password, name, provider = 'local', providerId = null }) {
    const existingUser = this.findByEmail(email);
    if (existingUser) {
      throw new Error('User already exists');
    }

    const id = uuidv4();
    const hashedPassword = password ? await bcrypt.hash(password, 12) : null;
    
    const user = {
      id,
      email,
      password: hashedPassword,
      name,
      provider,
      providerId,
      twoFactorEnabled: false,
      twoFactorSecret: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    users.set(id, user);
    return this.sanitize(user);
  }

  /**
   * Find user by ID
   * @param {string} id - User ID
   * @returns {Object|null} User or null
   */
  static findById(id) {
    return users.get(id) || null;
  }

  /**
   * Find user by email
   * @param {string} email - User email
   * @returns {Object|null} User or null
   */
  static findByEmail(email) {
    for (const user of users.values()) {
      if (user.email === email) {
        return user;
      }
    }
    return null;
  }

  /**
   * Find user by OAuth provider and provider ID
   * @param {string} provider - OAuth provider
   * @param {string} providerId - Provider user ID
   * @returns {Object|null} User or null
   */
  static findByProvider(provider, providerId) {
    for (const user of users.values()) {
      if (user.provider === provider && user.providerId === providerId) {
        return user;
      }
    }
    return null;
  }

  /**
   * Validate user password
   * @param {Object} user - User object
   * @param {string} password - Password to validate
   * @returns {boolean} Is valid
   */
  static async validatePassword(user, password) {
    if (!user.password) return false;
    return bcrypt.compare(password, user.password);
  }

  /**
   * Update user
   * @param {string} id - User ID
   * @param {Object} updates - Updates to apply
   * @returns {Object|null} Updated user or null
   */
  static async update(id, updates) {
    const user = users.get(id);
    if (!user) return null;

    if (updates.password) {
      updates.password = await bcrypt.hash(updates.password, 12);
    }

    const updatedUser = {
      ...user,
      ...updates,
      updatedAt: new Date(),
    };

    users.set(id, updatedUser);
    return this.sanitize(updatedUser);
  }

  /**
   * Enable 2FA for user
   * @param {string} userId - User ID
   * @param {string} secret - TOTP secret
   */
  static enable2FA(userId, secret) {
    const user = users.get(userId);
    if (user) {
      user.twoFactorEnabled = true;
      user.twoFactorSecret = secret;
      users.set(userId, user);
    }
  }

  /**
   * Disable 2FA for user
   * @param {string} userId - User ID
   */
  static disable2FA(userId) {
    const user = users.get(userId);
    if (user) {
      user.twoFactorEnabled = false;
      user.twoFactorSecret = null;
      users.set(userId, user);
    }
  }

  /**
   * Remove sensitive fields from user object
   * @param {Object} user - User object
   * @returns {Object} Sanitized user
   */
  static sanitize(user) {
    if (!user) return null;
    // eslint-disable-next-line no-unused-vars
    const { password, twoFactorSecret, ...sanitized } = user;
    return sanitized;
  }
}

class TokenModel {
  /**
   * Store refresh token
   * @param {string} userId - User ID
   * @param {string} token - Refresh token
   */
  static storeRefreshToken(userId, token) {
    const tokens = refreshTokens.get(userId) || [];
    tokens.push({
      token,
      createdAt: new Date(),
    });
    refreshTokens.set(userId, tokens);
  }

  /**
   * Validate refresh token
   * @param {string} userId - User ID
   * @param {string} token - Refresh token
   * @returns {boolean} Is valid
   */
  static validateRefreshToken(userId, token) {
    const tokens = refreshTokens.get(userId) || [];
    return tokens.some(t => t.token === token);
  }

  /**
   * Revoke refresh token
   * @param {string} userId - User ID
   * @param {string} token - Refresh token to revoke
   */
  static revokeRefreshToken(userId, token) {
    const tokens = refreshTokens.get(userId) || [];
    refreshTokens.set(userId, tokens.filter(t => t.token !== token));
  }

  /**
   * Revoke all refresh tokens for user
   * @param {string} userId - User ID
   */
  static revokeAllRefreshTokens(userId) {
    refreshTokens.delete(userId);
  }
}

class MagicLinkModel {
  /**
   * Create a magic link token
   * @param {string} email - User email
   * @returns {string} Magic link token
   */
  static create(email) {
    const token = uuidv4();
    magicLinks.set(token, {
      email,
      createdAt: new Date(),
      used: false,
    });
    return token;
  }

  /**
   * Validate magic link token
   * @param {string} token - Magic link token
   * @param {number} expiryMs - Expiry time in milliseconds
   * @returns {Object|null} Magic link data or null
   */
  static validate(token, expiryMs) {
    const link = magicLinks.get(token);
    if (!link) return null;
    if (link.used) return null;
    
    const now = new Date();
    const elapsed = now - link.createdAt;
    if (elapsed > expiryMs) {
      magicLinks.delete(token);
      return null;
    }
    
    return link;
  }

  /**
   * Mark magic link as used
   * @param {string} token - Magic link token
   */
  static markUsed(token) {
    const link = magicLinks.get(token);
    if (link) {
      link.used = true;
      magicLinks.set(token, link);
    }
  }
}

module.exports = {
  UserModel,
  TokenModel,
  MagicLinkModel,
};

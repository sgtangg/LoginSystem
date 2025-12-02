/**
 * Middleware Index
 * Exports all middleware modules
 */

const { authenticate, optionalAuth } = require('./auth');
const {
  generalLimiter,
  authLimiter,
  twoFactorLimiter,
  magicLinkLimiter,
} = require('./rateLimiter');
const {
  handleValidationErrors,
  validateRegistration,
  validateLogin,
  validateRefreshToken,
  validateTOTP,
  validate2FALogin,
  validateMagicLinkRequest,
  validate2FAEnable,
} = require('./validation');

module.exports = {
  // Auth middleware
  authenticate,
  optionalAuth,
  
  // Rate limiters
  generalLimiter,
  authLimiter,
  twoFactorLimiter,
  magicLinkLimiter,
  
  // Validators
  handleValidationErrors,
  validateRegistration,
  validateLogin,
  validateRefreshToken,
  validateTOTP,
  validate2FALogin,
  validateMagicLinkRequest,
  validate2FAEnable,
};

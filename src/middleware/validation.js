/**
 * Input Validation Middleware
 * Provides validation chains for authentication endpoints
 */

const { body, validationResult } = require('express-validator');

// Common validation messages
const TOTP_MESSAGES = {
  LENGTH: 'TOTP token must be 6 digits',
  NUMERIC: 'TOTP token must contain only numbers',
};

/**
 * Create TOTP token validation chain
 * @param {string} fieldName - The field name to validate
 * @returns {Object} Express validator chain
 */
const createTOTPValidation = (fieldName = 'token') => {
  return body(fieldName)
    .isLength({ min: 6, max: 6 })
    .withMessage(TOTP_MESSAGES.LENGTH)
    .isNumeric()
    .withMessage(TOTP_MESSAGES.NUMERIC);
};

/**
 * Handle validation errors
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map(err => ({
        field: err.path,
        message: err.msg,
      })),
    });
  }
  next();
};

/**
 * Validation for user registration
 */
const validateRegistration = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  handleValidationErrors,
];

/**
 * Validation for user login
 */
const validateLogin = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors,
];

/**
 * Validation for refresh token
 */
const validateRefreshToken = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required'),
  handleValidationErrors,
];

/**
 * Validation for TOTP token
 */
const validateTOTP = [
  createTOTPValidation('token'),
  handleValidationErrors,
];

/**
 * Validation for 2FA verification during login
 */
const validate2FALogin = [
  body('tempToken')
    .notEmpty()
    .withMessage('Temporary token is required'),
  createTOTPValidation('token'),
  handleValidationErrors,
];

/**
 * Validation for magic link request
 */
const validateMagicLinkRequest = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  handleValidationErrors,
];

/**
 * Validation for 2FA enable
 */
const validate2FAEnable = [
  body('secret')
    .notEmpty()
    .withMessage('Secret is required'),
  createTOTPValidation('token'),
  handleValidationErrors,
];

module.exports = {
  handleValidationErrors,
  validateRegistration,
  validateLogin,
  validateRefreshToken,
  validateTOTP,
  validate2FALogin,
  validateMagicLinkRequest,
  validate2FAEnable,
};

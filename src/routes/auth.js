/**
 * Authentication Routes
 * Defines all authentication-related endpoints
 */

const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { OAuthService } = require('../auth');
const {
  authenticate,
  authLimiter,
  twoFactorLimiter,
  magicLinkLimiter,
  validateRegistration,
  validateLogin,
  validateRefreshToken,
  validate2FALogin,
  validateMagicLinkRequest,
  validate2FAEnable,
  validateTOTP,
} = require('../middleware');

// =============================================================================
// Basic Authentication Routes
// =============================================================================

/**
 * @route POST /auth/register
 * @desc Register a new user
 * @access Public
 */
router.post('/register', authLimiter, validateRegistration, authController.register);

/**
 * @route POST /auth/login
 * @desc Login with email and password
 * @access Public
 */
router.post('/login', authLimiter, validateLogin, authController.login);

/**
 * @route POST /auth/logout
 * @desc Logout user (revoke refresh token)
 * @access Private
 */
router.post('/logout', authenticate, authController.logout);

/**
 * @route POST /auth/logout-all
 * @desc Logout from all devices (revoke all refresh tokens)
 * @access Private
 */
router.post('/logout-all', authenticate, authController.logoutAll);

/**
 * @route POST /auth/refresh
 * @desc Refresh access token using refresh token
 * @access Public
 */
router.post('/refresh', validateRefreshToken, authController.refreshToken);

/**
 * @route GET /auth/me
 * @desc Get current user profile
 * @access Private
 */
router.get('/me', authenticate, authController.getProfile);

// =============================================================================
// Two-Factor Authentication Routes
// =============================================================================

/**
 * @route POST /auth/2fa/verify
 * @desc Verify 2FA token during login
 * @access Public (with temp token)
 */
router.post('/2fa/verify', twoFactorLimiter, validate2FALogin, authController.verify2FA);

/**
 * @route POST /auth/2fa/setup
 * @desc Generate 2FA secret and QR code
 * @access Private
 */
router.post('/2fa/setup', authenticate, authController.setup2FA);

/**
 * @route POST /auth/2fa/enable
 * @desc Enable 2FA after verifying token
 * @access Private
 */
router.post('/2fa/enable', authenticate, validate2FAEnable, authController.enable2FA);

/**
 * @route POST /auth/2fa/disable
 * @desc Disable 2FA
 * @access Private
 */
router.post('/2fa/disable', authenticate, validateTOTP, authController.disable2FA);

// =============================================================================
// Magic Link Authentication Routes
// =============================================================================

/**
 * @route POST /auth/magic-link/request
 * @desc Request a magic link for passwordless login
 * @access Public
 */
router.post('/magic-link/request', magicLinkLimiter, validateMagicLinkRequest, authController.requestMagicLink);

/**
 * @route GET /auth/magic-link/verify
 * @desc Verify magic link and login
 * @access Public
 */
router.get('/magic-link/verify', authController.verifyMagicLink);

// =============================================================================
// OAuth Routes
// =============================================================================

/**
 * @route GET /auth/google
 * @desc Initiate Google OAuth login
 * @access Public
 */
router.get('/google', OAuthService.authenticate('google'));

/**
 * @route GET /auth/google/callback
 * @desc Google OAuth callback
 * @access Public
 */
router.get(
  '/google/callback',
  OAuthService.callback('google'),
  authController.oauthSuccess,
);

/**
 * @route GET /auth/github
 * @desc Initiate GitHub OAuth login
 * @access Public
 */
router.get('/github', OAuthService.authenticate('github'));

/**
 * @route GET /auth/github/callback
 * @desc GitHub OAuth callback
 * @access Public
 */
router.get(
  '/github/callback',
  OAuthService.callback('github'),
  authController.oauthSuccess,
);

/**
 * @route GET /auth/login/failed
 * @desc OAuth login failure handler
 * @access Public
 */
router.get('/login/failed', authController.oauthFailure);

module.exports = router;

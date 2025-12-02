/**
 * Authentication Controller
 * Handles HTTP requests for authentication
 */

const {
  BasicAuthService,
  TwoFactorAuthService,
  MagicLinkService,
} = require('../auth');

/**
 * Register a new user
 * POST /auth/register
 */
const register = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const result = await BasicAuthService.register({ email, password, name });
    
    res.status(201).json({
      message: 'User registered successfully',
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (error) {
    if (error.message === 'User already exists') {
      return res.status(409).json({
        error: 'Registration failed',
        message: 'A user with this email already exists',
      });
    }
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Registration failed',
      message: 'An error occurred during registration',
    });
  }
};

/**
 * Login with email and password
 * POST /auth/login
 */
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await BasicAuthService.login(email, password);
    
    if (!result) {
      return res.status(401).json({
        error: 'Login failed',
        message: 'Invalid email or password',
      });
    }

    if (result.requiresTwoFactor) {
      return res.status(200).json({
        message: 'Two-factor authentication required',
        requiresTwoFactor: true,
        tempToken: result.tempToken,
      });
    }

    res.status(200).json({
      message: 'Login successful',
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Login failed',
      message: 'An error occurred during login',
    });
  }
};

/**
 * Verify 2FA token after initial login
 * POST /auth/2fa/verify
 */
const verify2FA = (req, res) => {
  try {
    const { tempToken, token } = req.body;
    const result = TwoFactorAuthService.verifyLogin(tempToken, token);
    
    if (!result) {
      return res.status(401).json({
        error: 'Verification failed',
        message: 'Invalid or expired verification code',
      });
    }

    res.status(200).json({
      message: 'Two-factor authentication successful',
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (error) {
    console.error('2FA verification error:', error);
    res.status(500).json({
      error: 'Verification failed',
      message: 'An error occurred during verification',
    });
  }
};

/**
 * Logout user
 * POST /auth/logout
 */
const logout = (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (req.user && refreshToken) {
      BasicAuthService.logout(req.user.id, refreshToken);
    }
    
    res.status(200).json({
      message: 'Logged out successfully',
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      error: 'Logout failed',
      message: 'An error occurred during logout',
    });
  }
};

/**
 * Logout from all devices
 * POST /auth/logout-all
 */
const logoutAll = (req, res) => {
  try {
    BasicAuthService.logoutAll(req.user.id);
    
    res.status(200).json({
      message: 'Logged out from all devices successfully',
    });
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({
      error: 'Logout failed',
      message: 'An error occurred during logout',
    });
  }
};

/**
 * Refresh access token
 * POST /auth/refresh
 */
const refreshToken = async (req, res) => {
  try {
    const { refreshToken: token } = req.body;
    const result = await BasicAuthService.refreshAccessToken(token);
    
    if (!result) {
      return res.status(401).json({
        error: 'Token refresh failed',
        message: 'Invalid or expired refresh token',
      });
    }

    res.status(200).json({
      message: 'Token refreshed successfully',
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      error: 'Token refresh failed',
      message: 'An error occurred during token refresh',
    });
  }
};

/**
 * Get current user profile
 * GET /auth/me
 */
const getProfile = (req, res) => {
  res.status(200).json({
    user: req.user,
  });
};

/**
 * Generate 2FA secret and QR code
 * POST /auth/2fa/setup
 */
const setup2FA = async (req, res) => {
  try {
    const result = await TwoFactorAuthService.generateSecret(req.user.id);
    
    res.status(200).json({
      message: 'Scan the QR code with your authenticator app',
      secret: result.secret,
      qrCode: result.qrCode,
    });
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({
      error: '2FA setup failed',
      message: 'An error occurred during 2FA setup',
    });
  }
};

/**
 * Enable 2FA after verifying token
 * POST /auth/2fa/enable
 */
const enable2FA = (req, res) => {
  try {
    const { secret, token } = req.body;
    const success = TwoFactorAuthService.verifyAndEnable(req.user.id, secret, token);
    
    if (!success) {
      return res.status(400).json({
        error: '2FA enable failed',
        message: 'Invalid verification code',
      });
    }

    // Generate backup codes
    const backupCodes = TwoFactorAuthService.generateBackupCodes();

    res.status(200).json({
      message: 'Two-factor authentication enabled successfully',
      backupCodes,
    });
  } catch (error) {
    console.error('2FA enable error:', error);
    res.status(500).json({
      error: '2FA enable failed',
      message: 'An error occurred while enabling 2FA',
    });
  }
};

/**
 * Disable 2FA
 * POST /auth/2fa/disable
 */
const disable2FA = (req, res) => {
  try {
    const { token } = req.body;
    const success = TwoFactorAuthService.disable(req.user.id, token);
    
    if (!success) {
      return res.status(400).json({
        error: '2FA disable failed',
        message: 'Invalid verification code',
      });
    }

    res.status(200).json({
      message: 'Two-factor authentication disabled successfully',
    });
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({
      error: '2FA disable failed',
      message: 'An error occurred while disabling 2FA',
    });
  }
};

/**
 * Request magic link
 * POST /auth/magic-link/request
 */
const requestMagicLink = async (req, res) => {
  try {
    const { email } = req.body;
    const result = await MagicLinkService.sendMagicLink(email);
    
    if (!result.success) {
      return res.status(500).json({
        error: 'Magic link failed',
        message: result.error,
      });
    }

    // In production, don't expose token. Only send generic message.
    const response = {
      message: 'If an account exists with this email, you will receive a login link shortly',
    };

    // Include token in development for testing
    if (process.env.NODE_ENV === 'development' && result.token) {
      response.token = result.token;
      response.magicLinkUrl = result.magicLinkUrl;
    }

    res.status(200).json(response);
  } catch (error) {
    console.error('Magic link request error:', error);
    res.status(500).json({
      error: 'Magic link failed',
      message: 'An error occurred while sending magic link',
    });
  }
};

/**
 * Verify magic link
 * GET /auth/magic-link/verify
 */
const verifyMagicLink = async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.status(400).json({
        error: 'Verification failed',
        message: 'Magic link token is required',
      });
    }

    const result = await MagicLinkService.verifyMagicLink(token);
    
    if (!result) {
      return res.status(401).json({
        error: 'Verification failed',
        message: 'Invalid or expired magic link',
      });
    }

    if (result.requiresTwoFactor) {
      return res.status(200).json({
        message: 'Two-factor authentication required',
        requiresTwoFactor: true,
        tempToken: result.tempToken,
      });
    }

    res.status(200).json({
      message: 'Login successful',
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (error) {
    console.error('Magic link verification error:', error);
    res.status(500).json({
      error: 'Verification failed',
      message: 'An error occurred during verification',
    });
  }
};

/**
 * OAuth success callback
 * Handles successful OAuth authentication
 */
const oauthSuccess = (req, res) => {
  if (req.user) {
    res.status(200).json({
      message: 'OAuth login successful',
      user: req.user.user,
      accessToken: req.user.accessToken,
      refreshToken: req.user.refreshToken,
    });
  } else {
    res.status(401).json({
      error: 'OAuth failed',
      message: 'OAuth authentication failed',
    });
  }
};

/**
 * OAuth failure callback
 */
const oauthFailure = (req, res) => {
  res.status(401).json({
    error: 'OAuth failed',
    message: 'OAuth authentication failed',
  });
};

module.exports = {
  register,
  login,
  verify2FA,
  logout,
  logoutAll,
  refreshToken,
  getProfile,
  setup2FA,
  enable2FA,
  disable2FA,
  requestMagicLink,
  verifyMagicLink,
  oauthSuccess,
  oauthFailure,
};

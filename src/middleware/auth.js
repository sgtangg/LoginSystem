/**
 * Authentication Middleware
 * Handles JWT authentication for protected routes
 */

const JWTAuthService = require('../auth/JWTAuthService');
const { UserModel } = require('../models/User');

/**
 * Authenticate request using JWT
 * Requires valid access token in Authorization header
 */
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = JWTAuthService.extractTokenFromHeader(authHeader);

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'No access token provided',
    });
  }

  const decoded = JWTAuthService.verifyAccessToken(token);
  if (!decoded) {
    return res.status(401).json({
      error: 'Invalid token',
      message: 'Access token is invalid or expired',
    });
  }

  const user = UserModel.findById(decoded.userId);
  if (!user) {
    return res.status(401).json({
      error: 'User not found',
      message: 'User associated with token no longer exists',
    });
  }

  // Attach user to request
  req.user = UserModel.sanitize(user);
  req.token = token;
  next();
};

/**
 * Optional authentication
 * Attaches user if valid token present, but doesn't require it
 */
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = JWTAuthService.extractTokenFromHeader(authHeader);

  if (token) {
    const decoded = JWTAuthService.verifyAccessToken(token);
    if (decoded) {
      const user = UserModel.findById(decoded.userId);
      if (user) {
        req.user = UserModel.sanitize(user);
        req.token = token;
      }
    }
  }

  next();
};

module.exports = {
  authenticate,
  optionalAuth,
};

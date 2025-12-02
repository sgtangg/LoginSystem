/**
 * Rate Limiting Middleware
 * Prevents brute-force attacks on authentication endpoints
 */

const rateLimit = require('express-rate-limit');
const config = require('../config');

/**
 * General rate limiter for API
 */
const generalLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  message: {
    error: 'Too many requests',
    message: 'You have exceeded the rate limit. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Strict rate limiter for authentication endpoints
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: {
    error: 'Too many authentication attempts',
    message: 'You have exceeded the authentication rate limit. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful logins
});

/**
 * Very strict rate limiter for 2FA verification
 */
const twoFactorLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    error: 'Too many 2FA attempts',
    message: 'You have exceeded the 2FA verification rate limit. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rate limiter for magic link requests
 */
const magicLinkLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 magic link requests per hour
  message: {
    error: 'Too many magic link requests',
    message: 'You have exceeded the magic link request limit. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = {
  generalLimiter,
  authLimiter,
  twoFactorLimiter,
  magicLinkLimiter,
};

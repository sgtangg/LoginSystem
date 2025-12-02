/**
 * Application Configuration
 * Loads configuration from environment variables with sensible defaults
 */

require('dotenv').config();

// Validate JWT secret in production
const getJWTSecret = () => {
  const secret = process.env.JWT_SECRET;
  if (!secret && process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET environment variable is required in production');
  }
  // Use a development-only default that clearly indicates it should be changed
  return secret || 'DEVELOPMENT_ONLY_SECRET_CHANGE_IN_PRODUCTION';
};

module.exports = {
  // Server Configuration
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // JWT Configuration
  jwt: {
    secret: getJWTSecret(),
    accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
  },
  
  // Database Configuration (for future implementation)
  database: {
    url: process.env.DATABASE_URL || 'mongodb://localhost:27017/loginsystem',
  },
  
  // OAuth Configuration
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackUrl: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID || '',
      clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
      callbackUrl: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/auth/github/callback',
    },
  },
  
  // Email Configuration (for Magic Link authentication)
  email: {
    host: process.env.EMAIL_HOST || 'smtp.ethereal.email',
    port: parseInt(process.env.EMAIL_PORT, 10) || 587,
    secure: process.env.EMAIL_SECURE === 'true',
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || '',
    from: process.env.EMAIL_FROM || 'noreply@loginsystem.com',
  },
  
  // Magic Link Configuration
  magicLink: {
    expiry: parseInt(process.env.MAGIC_LINK_EXPIRY, 10) || 15 * 60 * 1000, // 15 minutes
    baseUrl: process.env.MAGIC_LINK_BASE_URL || 'http://localhost:3000',
  },
  
  // Two-Factor Authentication Configuration
  twoFactor: {
    issuer: process.env.TOTP_ISSUER || 'LoginSystem',
    window: parseInt(process.env.TOTP_WINDOW, 10) || 1,
  },
  
  // Rate Limiting Configuration
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100, // max requests per window
  },
};

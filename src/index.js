/**
 * LoginSystem - Pusat Login dengan berbagai teknis Auth
 * A centralized login system with various authentication methods
 * 
 * Supported authentication methods:
 * - Basic (Username/Password)
 * - JWT (JSON Web Tokens)
 * - OAuth (Google, GitHub)
 * - 2FA (TOTP - Time-based One-Time Password)
 * - Magic Link (Passwordless email authentication)
 */

const express = require('express');
const cors = require('cors');
const passport = require('passport');
const config = require('./config');
const { authRoutes } = require('./routes');
const { OAuthService, MagicLinkService } = require('./auth');
const { generalLimiter } = require('./middleware');

// Create Express app
const app = express();

// =============================================================================
// Middleware Setup
// =============================================================================

// Enable CORS
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
}));

// Parse JSON bodies
app.use(express.json());

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

// Apply general rate limiting
app.use(generalLimiter);

// Initialize Passport
app.use(passport.initialize());

// Initialize OAuth strategies
OAuthService.initialize();

// Initialize Magic Link service
MagicLinkService.initialize();

// =============================================================================
// Routes
// =============================================================================

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: require('../package.json').version,
  });
});

// API info endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    name: 'LoginSystem API',
    description: 'Pusat Login dengan berbagai teknis Auth',
    version: require('../package.json').version,
    endpoints: {
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login',
        logout: 'POST /auth/logout',
        logoutAll: 'POST /auth/logout-all',
        refresh: 'POST /auth/refresh',
        profile: 'GET /auth/me',
      },
      twoFactor: {
        verify: 'POST /auth/2fa/verify',
        setup: 'POST /auth/2fa/setup',
        enable: 'POST /auth/2fa/enable',
        disable: 'POST /auth/2fa/disable',
      },
      magicLink: {
        request: 'POST /auth/magic-link/request',
        verify: 'GET /auth/magic-link/verify',
      },
      oauth: {
        google: 'GET /auth/google',
        googleCallback: 'GET /auth/google/callback',
        github: 'GET /auth/github',
        githubCallback: 'GET /auth/github/callback',
      },
    },
    authMethods: [
      'Basic (Username/Password)',
      'JWT (JSON Web Tokens)',
      'OAuth (Google, GitHub)',
      '2FA (TOTP)',
      'Magic Link (Passwordless)',
    ],
  });
});

// Authentication routes
app.use('/auth', authRoutes);

// =============================================================================
// Error Handling
// =============================================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.path} not found`,
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // Don't expose internal errors in production
  const message = config.nodeEnv === 'development' 
    ? err.message 
    : 'An internal error occurred';
  
  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    message,
    ...(config.nodeEnv === 'development' && { stack: err.stack }),
  });
});

// =============================================================================
// Server Startup
// =============================================================================

// Only start server if not in test mode
if (process.env.NODE_ENV !== 'test') {
  app.listen(config.port, () => {
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   🔐 LoginSystem - Pusat Login dengan berbagai teknis Auth    ║
║                                                                ║
║   Server running on port ${config.port}                              ║
║   Environment: ${config.nodeEnv}                               ║
║                                                                ║
║   Available Authentication Methods:                            ║
║   ✓ Basic (Username/Password)                                  ║
║   ✓ JWT (JSON Web Tokens)                                      ║
║   ✓ OAuth (Google, GitHub)                                     ║
║   ✓ 2FA (TOTP)                                                 ║
║   ✓ Magic Link (Passwordless)                                  ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    `);
  });
}

// Export for testing
module.exports = app;

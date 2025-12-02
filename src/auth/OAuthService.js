/**
 * OAuth Authentication Service
 * Handles OAuth authentication with Google and GitHub
 */

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const config = require('../config');
const { UserModel, TokenModel } = require('../models/User');
const BasicAuthService = require('./BasicAuthService');

class OAuthService {
  /**
   * Initialize OAuth strategies
   */
  static initialize() {
    // Configure Google OAuth Strategy
    if (config.oauth.google.clientId && config.oauth.google.clientSecret) {
      passport.use(
        new GoogleStrategy(
          {
            clientID: config.oauth.google.clientId,
            clientSecret: config.oauth.google.clientSecret,
            callbackURL: config.oauth.google.callbackUrl,
            scope: ['profile', 'email'],
          },
          this.googleCallback,
        ),
      );
    }

    // Configure GitHub OAuth Strategy
    if (config.oauth.github.clientId && config.oauth.github.clientSecret) {
      passport.use(
        new GitHubStrategy(
          {
            clientID: config.oauth.github.clientId,
            clientSecret: config.oauth.github.clientSecret,
            callbackURL: config.oauth.github.callbackUrl,
            scope: ['user:email'],
          },
          this.githubCallback,
        ),
      );
    }

    // Serialize user for session
    passport.serializeUser((user, done) => {
      done(null, user.id);
    });

    // Deserialize user from session
    passport.deserializeUser((id, done) => {
      const user = UserModel.findById(id);
      done(null, UserModel.sanitize(user));
    });
  }

  /**
   * Google OAuth callback
   */
  static async googleCallback(accessToken, refreshToken, profile, done) {
    try {
      const result = await OAuthService.handleOAuthLogin('google', profile);
      done(null, result);
    } catch (error) {
      done(error, null);
    }
  }

  /**
   * GitHub OAuth callback
   */
  static async githubCallback(accessToken, refreshToken, profile, done) {
    try {
      const result = await OAuthService.handleOAuthLogin('github', profile);
      done(null, result);
    } catch (error) {
      done(error, null);
    }
  }

  /**
   * Handle OAuth login/registration
   * @param {string} provider - OAuth provider name
   * @param {Object} profile - OAuth profile
   * @returns {Object} User and tokens
   */
  static async handleOAuthLogin(provider, profile) {
    const providerId = profile.id;
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : `${provider}_${providerId}@oauth.local`;
    const name = profile.displayName || profile.username || 'OAuth User';

    // Try to find existing user by provider
    let user = UserModel.findByProvider(provider, providerId);

    if (!user) {
      // Try to find by email
      user = UserModel.findByEmail(email);
      
      if (user) {
        // Link OAuth to existing user
        await UserModel.update(user.id, {
          provider,
          providerId,
        });
        user = UserModel.findById(user.id);
      } else {
        // Create new user
        user = await UserModel.create({
          email,
          name,
          provider,
          providerId,
          password: null,
        });
        user = UserModel.findByEmail(email);
      }
    }

    // Generate tokens
    const tokens = BasicAuthService.generateTokens(user);
    TokenModel.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: UserModel.sanitize(user),
      ...tokens,
    };
  }

  /**
   * Get passport middleware for provider
   * @param {string} provider - Provider name (google, github)
   * @returns {Function} Passport authenticate middleware
   */
  static authenticate(provider) {
    const options = {
      session: false,
    };

    if (provider === 'google') {
      options.scope = ['profile', 'email'];
    } else if (provider === 'github') {
      options.scope = ['user:email'];
    }

    return passport.authenticate(provider, options);
  }

  /**
   * Get passport callback middleware for provider
   * @param {string} provider - Provider name (google, github)
   * @returns {Function} Passport authenticate middleware
   */
  static callback(provider) {
    return passport.authenticate(provider, {
      session: false,
      failureRedirect: '/auth/login/failed',
    });
  }
}

module.exports = OAuthService;

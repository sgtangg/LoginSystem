/**
 * Auth Services Index
 * Exports all authentication services
 */

const BasicAuthService = require('./BasicAuthService');
const JWTAuthService = require('./JWTAuthService');
const OAuthService = require('./OAuthService');
const TwoFactorAuthService = require('./TwoFactorAuthService');
const MagicLinkService = require('./MagicLinkService');

module.exports = {
  BasicAuthService,
  JWTAuthService,
  OAuthService,
  TwoFactorAuthService,
  MagicLinkService,
};

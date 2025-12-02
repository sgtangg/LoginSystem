# LoginSystem

🔐 **Pusat Login dengan berbagai teknis Auth** - A centralized login system with various authentication methods.

## Features

This login system supports multiple authentication techniques:

- ✅ **Basic Authentication** - Username/Password login with secure password hashing (bcrypt)
- ✅ **JWT Authentication** - Stateless authentication using JSON Web Tokens
- ✅ **OAuth 2.0** - Social login with Google and GitHub
- ✅ **Two-Factor Authentication (2FA)** - TOTP-based 2FA with QR code setup
- ✅ **Magic Link** - Passwordless email authentication

## Quick Start

### Prerequisites

- Node.js >= 18.x
- npm >= 9.x

### Installation

```bash
# Clone the repository
git clone https://github.com/sgtangg/LoginSystem.git
cd LoginSystem

# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Start the server
npm start
```

### Development

```bash
# Start with hot reload
npm run dev

# Run tests
npm test

# Run linting
npm run lint
```

## API Endpoints

### Basic Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Login with email/password |
| POST | `/auth/logout` | Logout (revoke refresh token) |
| POST | `/auth/logout-all` | Logout from all devices |
| POST | `/auth/refresh` | Refresh access token |
| GET | `/auth/me` | Get current user profile |

### Two-Factor Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/2fa/setup` | Generate 2FA secret and QR code |
| POST | `/auth/2fa/enable` | Enable 2FA after verification |
| POST | `/auth/2fa/disable` | Disable 2FA |
| POST | `/auth/2fa/verify` | Verify 2FA during login |

### Magic Link (Passwordless)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/magic-link/request` | Request a magic link |
| GET | `/auth/magic-link/verify` | Verify magic link and login |

### OAuth

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/google` | Initiate Google OAuth |
| GET | `/auth/google/callback` | Google OAuth callback |
| GET | `/auth/github` | Initiate GitHub OAuth |
| GET | `/auth/github/callback` | GitHub OAuth callback |

## Usage Examples

### Register a new user

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123",
    "name": "John Doe"
  }'
```

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

### Access protected route

```bash
curl -X GET http://localhost:3000/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh token

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### Setup 2FA

```bash
# 1. Generate secret and QR code
curl -X POST http://localhost:3000/auth/2fa/setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# 2. Scan QR code with authenticator app and enable
curl -X POST http://localhost:3000/auth/2fa/enable \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "GENERATED_SECRET",
    "token": "123456"
  }'
```

### Request Magic Link

```bash
curl -X POST http://localhost:3000/auth/magic-link/request \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

## Configuration

Configure the application using environment variables. See `.env.example` for all available options.

### Key Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `JWT_SECRET` | Secret key for JWT signing | (required in production) |
| `JWT_ACCESS_EXPIRY` | Access token expiry | 15m |
| `JWT_REFRESH_EXPIRY` | Refresh token expiry | 7d |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret | - |
| `EMAIL_HOST` | SMTP host for magic links | smtp.ethereal.email |

## Security Features

- 🔒 Password hashing with bcrypt (12 rounds)
- 🔒 JWT tokens with configurable expiry
- 🔒 Refresh token rotation
- 🔒 Rate limiting on authentication endpoints
- 🔒 Input validation and sanitization
- 🔒 CORS protection
- 🔒 TOTP-based 2FA with backup codes

## Project Structure

```
LoginSystem/
├── src/
│   ├── auth/                 # Authentication services
│   │   ├── BasicAuthService.js
│   │   ├── JWTAuthService.js
│   │   ├── OAuthService.js
│   │   ├── TwoFactorAuthService.js
│   │   ├── MagicLinkService.js
│   │   └── index.js
│   ├── config/               # Configuration
│   │   └── index.js
│   ├── controllers/          # Request handlers
│   │   └── authController.js
│   ├── middleware/           # Express middleware
│   │   ├── auth.js
│   │   ├── rateLimiter.js
│   │   ├── validation.js
│   │   └── index.js
│   ├── models/               # Data models
│   │   └── User.js
│   ├── routes/               # API routes
│   │   ├── auth.js
│   │   └── index.js
│   └── index.js              # Application entry point
├── tests/                    # Test files
│   └── auth.test.js
├── .env.example              # Environment template
├── .gitignore
├── jest.config.js
├── package.json
└── README.md
```

## License

MIT
/**
 * Authentication Tests
 * Tests for all authentication methods
 */

const request = require('supertest');
const app = require('../src/index');

describe('LoginSystem Authentication', () => {
  let accessToken;
  let refreshToken;
  let testUser = {
    email: 'test@example.com',
    password: 'TestPassword123',
    name: 'Test User',
  };

  // ==========================================================================
  // Basic Authentication Tests
  // ==========================================================================

  describe('Basic Authentication', () => {
    describe('POST /auth/register', () => {
      it('should register a new user successfully', async () => {
        const res = await request(app)
          .post('/auth/register')
          .send(testUser);

        expect(res.status).toBe(201);
        expect(res.body.message).toBe('User registered successfully');
        expect(res.body.user.email).toBe(testUser.email);
        expect(res.body.accessToken).toBeDefined();
        expect(res.body.refreshToken).toBeDefined();
        expect(res.body.user.password).toBeUndefined();

        accessToken = res.body.accessToken;
        refreshToken = res.body.refreshToken;
      });

      it('should fail with existing email', async () => {
        const res = await request(app)
          .post('/auth/register')
          .send(testUser);

        expect(res.status).toBe(409);
        expect(res.body.error).toBe('Registration failed');
      });

      it('should fail with invalid email', async () => {
        const res = await request(app)
          .post('/auth/register')
          .send({
            email: 'invalid-email',
            password: 'TestPassword123',
          });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
      });

      it('should fail with weak password', async () => {
        const res = await request(app)
          .post('/auth/register')
          .send({
            email: 'weak@example.com',
            password: 'weak',
          });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
      });
    });

    describe('POST /auth/login', () => {
      it('should login successfully with correct credentials', async () => {
        const res = await request(app)
          .post('/auth/login')
          .send({
            email: testUser.email,
            password: testUser.password,
          });

        expect(res.status).toBe(200);
        expect(res.body.message).toBe('Login successful');
        expect(res.body.user.email).toBe(testUser.email);
        expect(res.body.accessToken).toBeDefined();
        expect(res.body.refreshToken).toBeDefined();

        accessToken = res.body.accessToken;
        refreshToken = res.body.refreshToken;
      });

      it('should fail with wrong password', async () => {
        const res = await request(app)
          .post('/auth/login')
          .send({
            email: testUser.email,
            password: 'WrongPassword123',
          });

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Login failed');
      });

      it('should fail with non-existent email', async () => {
        const res = await request(app)
          .post('/auth/login')
          .send({
            email: 'nonexistent@example.com',
            password: 'TestPassword123',
          });

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Login failed');
      });
    });

    describe('GET /auth/me', () => {
      it('should get user profile with valid token', async () => {
        const res = await request(app)
          .get('/auth/me')
          .set('Authorization', `Bearer ${accessToken}`);

        expect(res.status).toBe(200);
        expect(res.body.user.email).toBe(testUser.email);
        expect(res.body.user.password).toBeUndefined();
      });

      it('should fail without token', async () => {
        const res = await request(app).get('/auth/me');

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Authentication required');
      });

      it('should fail with invalid token', async () => {
        const res = await request(app)
          .get('/auth/me')
          .set('Authorization', 'Bearer invalid-token');

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Invalid token');
      });
    });

    describe('POST /auth/refresh', () => {
      it('should refresh tokens successfully', async () => {
        const res = await request(app)
          .post('/auth/refresh')
          .send({ refreshToken });

        expect(res.status).toBe(200);
        expect(res.body.message).toBe('Token refreshed successfully');
        expect(res.body.accessToken).toBeDefined();
        expect(res.body.refreshToken).toBeDefined();

        // Update tokens for subsequent tests
        accessToken = res.body.accessToken;
        refreshToken = res.body.refreshToken;
      });

      it('should fail with invalid refresh token', async () => {
        const res = await request(app)
          .post('/auth/refresh')
          .send({ refreshToken: 'invalid-refresh-token' });

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Token refresh failed');
      });
    });

    describe('POST /auth/logout', () => {
      it('should logout successfully', async () => {
        const res = await request(app)
          .post('/auth/logout')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ refreshToken });

        expect(res.status).toBe(200);
        expect(res.body.message).toBe('Logged out successfully');
      });
    });
  });

  // ==========================================================================
  // Two-Factor Authentication Tests
  // ==========================================================================

  describe('Two-Factor Authentication', () => {
    let user2FAToken;
    let totpSecret;
    const user2FA = {
      email: 'twofa@example.com',
      password: 'TwoFaPassword123',
      name: '2FA User',
    };

    beforeAll(async () => {
      // Register and login user for 2FA tests
      await request(app).post('/auth/register').send(user2FA);
      const loginRes = await request(app)
        .post('/auth/login')
        .send({ email: user2FA.email, password: user2FA.password });
      
      user2FAToken = loginRes.body.accessToken;
    });

    describe('POST /auth/2fa/setup', () => {
      it('should generate 2FA secret and QR code', async () => {
        const res = await request(app)
          .post('/auth/2fa/setup')
          .set('Authorization', `Bearer ${user2FAToken}`);

        expect(res.status).toBe(200);
        expect(res.body.secret).toBeDefined();
        expect(res.body.qrCode).toBeDefined();
        expect(res.body.qrCode).toMatch(/^data:image\/png;base64,/);

        totpSecret = res.body.secret;
      });

      it('should fail without authentication', async () => {
        const res = await request(app).post('/auth/2fa/setup');

        expect(res.status).toBe(401);
      });
    });

    describe('POST /auth/2fa/enable', () => {
      it('should fail with invalid TOTP token', async () => {
        const res = await request(app)
          .post('/auth/2fa/enable')
          .set('Authorization', `Bearer ${user2FAToken}`)
          .send({
            secret: totpSecret,
            token: '000000',
          });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('2FA enable failed');
      });
    });
  });

  // ==========================================================================
  // Magic Link Authentication Tests
  // ==========================================================================

  describe('Magic Link Authentication', () => {
    const magicLinkEmail = 'magiclink@example.com';

    describe('POST /auth/magic-link/request', () => {
      it('should request magic link successfully', async () => {
        const res = await request(app)
          .post('/auth/magic-link/request')
          .send({ email: magicLinkEmail });

        expect(res.status).toBe(200);
        expect(res.body.message).toBeDefined();
      });

      it('should fail with invalid email', async () => {
        const res = await request(app)
          .post('/auth/magic-link/request')
          .send({ email: 'invalid-email' });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
      });
    });

    describe('GET /auth/magic-link/verify', () => {
      it('should fail with missing token', async () => {
        const res = await request(app).get('/auth/magic-link/verify');

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Verification failed');
      });

      it('should fail with invalid token', async () => {
        const res = await request(app)
          .get('/auth/magic-link/verify')
          .query({ token: 'invalid-token' });

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Verification failed');
      });
    });
  });

  // ==========================================================================
  // API Endpoint Tests
  // ==========================================================================

  describe('API Endpoints', () => {
    describe('GET /', () => {
      it('should return API info', async () => {
        const res = await request(app).get('/');

        expect(res.status).toBe(200);
        expect(res.body.name).toBe('LoginSystem API');
        expect(res.body.endpoints).toBeDefined();
        expect(res.body.authMethods).toBeDefined();
        expect(res.body.authMethods).toContain('Basic (Username/Password)');
        expect(res.body.authMethods).toContain('JWT (JSON Web Tokens)');
        expect(res.body.authMethods).toContain('OAuth (Google, GitHub)');
        expect(res.body.authMethods).toContain('2FA (TOTP)');
        expect(res.body.authMethods).toContain('Magic Link (Passwordless)');
      });
    });

    describe('GET /health', () => {
      it('should return health status', async () => {
        const res = await request(app).get('/health');

        expect(res.status).toBe(200);
        expect(res.body.status).toBe('healthy');
        expect(res.body.timestamp).toBeDefined();
      });
    });

    describe('404 Handler', () => {
      it('should return 404 for unknown routes', async () => {
        const res = await request(app).get('/unknown-route');

        expect(res.status).toBe(404);
        expect(res.body.error).toBe('Not Found');
      });
    });
  });
});

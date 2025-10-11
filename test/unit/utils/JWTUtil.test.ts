/**
 * Tests for JWT utility class
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JWTUtil } from "../../../src/utils/JWTUtil.js";
import type { JWTConfig } from "../../../src/types/index.js";

describe('JWTUtil', () => {
  let jwtUtil: JWTUtil;
  const testConfig: JWTConfig = {
    algorithm: 'HS256',
    secret: 'test-secret-key'
  };

  beforeEach(() => {
    jwtUtil = new JWTUtil(testConfig);
  });

  describe('Constructor', () => {
    it('should create instance with HS256 configuration', () => {
      expect(jwtUtil.getAlgorithm()).toBe('HS256');
    });

    it('should throw error for HS256 without secret', () => {
      expect(() => new JWTUtil({ algorithm: 'HS256' })).toThrow('JWT secret is required for HS256 algorithm');
    });

    it('should throw error for RS256 without keys', () => {
      expect(() => new JWTUtil({ algorithm: 'RS256' })).toThrow('Private and public keys are required for RS256 algorithm');
    });

    it('should use default values', () => {
      const defaultUtil = new JWTUtil({ secret: 'test-secret' });
      expect(defaultUtil.getAlgorithm()).toBe('HS256');
    });
  });

  describe('Token Generation', () => {
    it('should generate a valid JWT token', () => {
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600
      });

      expect(token).toBeTruthy();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    it('should generate access token with correct claims', () => {
      const token = jwtUtil.generateAccessToken({
        issuer: 'http://localhost:5173/oidc',
        clientId: 'test_client',
        userId: 'user123',
        expiresIn: 3600,
        scope: 'openid profile'
      });

      const decoded = jwtUtil.decodeToken(token);
      expect(decoded).toBeTruthy();
      expect(decoded!.iss).toBe('http://localhost:5173/oidc');
      expect(decoded!.aud).toBe('test_client');
      expect(decoded!.sub).toBe('user123');
      expect(decoded!.client_id).toBe('test_client');
      expect(decoded!.scope).toBe('openid profile');
    });

    it('should generate ID token with user profile claims', () => {
      const token = jwtUtil.generateIDToken({
        issuer: 'http://localhost:5173/oidc',
        clientId: 'test_client',
        userId: 'user123',
        expiresIn: 3600,
        nonce: 'test-nonce',
        userProfile: {
          name: 'Test User',
          email: 'test@example.com',
          email_verified: true
        }
      });

      const decoded = jwtUtil.decodeToken(token);
      expect(decoded).toBeTruthy();
      expect(decoded!.nonce).toBe('test-nonce');
      expect(decoded!.name).toBe('Test User');
      expect(decoded!.email).toBe('test@example.com');
      expect(decoded!.email_verified).toBe(true);
    });
  });

  describe('Token Validation', () => {
    it('should validate a valid token', () => {
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600
      });

      const result = jwtUtil.validateToken(token);
      expect(result.valid).toBe(true);
      expect(result.payload).toBeTruthy();
      expect(result.payload!.sub).toBe('user123');
    });

    it('should reject invalid token', () => {
      const result = jwtUtil.validateToken('invalid.token.here');
      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });

    it('should reject expired token', () => {
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: -1 // Already expired
      });

      const result = jwtUtil.validateToken(token);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should reject token with wrong secret', () => {
      const wrongUtil = new JWTUtil({ algorithm: 'HS256', secret: 'wrong-secret' });
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600
      });

      const result = wrongUtil.validateToken(token);
      expect(result.valid).toBe(false);
    });
  });

  describe('Token Type Detection', () => {
    it('should identify access tokens', () => {
      const token = jwtUtil.generateAccessToken({
        issuer: 'http://localhost:5173/oidc',
        clientId: 'test_client',
        userId: 'user123',
        expiresIn: 3600
      });

      const decoded = jwtUtil.decodeToken(token);
      expect(jwtUtil.isAccessToken(decoded!)).toBe(true);
      expect(jwtUtil.isIDToken(decoded!)).toBe(false);
    });

    it('should identify ID tokens', () => {
      const token = jwtUtil.generateIDToken({
        issuer: 'http://localhost:5173/oidc',
        clientId: 'test_client',
        userId: 'user123',
        expiresIn: 3600,
        nonce: 'test-nonce'
      });

      const decoded = jwtUtil.decodeToken(token);
      expect(jwtUtil.isIDToken(decoded!)).toBe(true);
      expect(jwtUtil.isAccessToken(decoded!)).toBe(false);
    });
  });

  describe('Token Decoding', () => {
    it('should decode token without verification', () => {
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600,
        additionalClaims: { custom: 'value' }
      });

      const decoded = jwtUtil.decodeToken(token);
      expect(decoded).toBeTruthy();
      expect(decoded!.iss).toBe('http://localhost:5173/oidc');
      expect(decoded!.custom).toBe('value');
    });

    it('should return null for invalid token', () => {
      const decoded = jwtUtil.decodeToken('invalid-token');
      expect(decoded).toBeNull();
    });
  });

  describe('OIDC Standard Claims Validation (Requirement 9.2)', () => {
    it('should generate ID token with all required OIDC standard claims', () => {
      const token = jwtUtil.generateIDToken({
        issuer: 'http://localhost:5173/oidc',
        clientId: 'test_client',
        userId: 'user123',
        expiresIn: 3600,
        nonce: 'test-nonce-123',
        userProfile: {
          name: 'Test User',
          email: 'test@example.com'
        }
      });

      const decoded = jwtUtil.decodeToken(token);
      expect(decoded).toBeTruthy();
      
      // Verify all required OIDC standard claims are present
      expect(decoded!.iss).toBe('http://localhost:5173/oidc'); // issuer
      expect(decoded!.aud).toBe('test_client'); // audience
      expect(decoded!.sub).toBe('user123'); // subject
      expect(decoded!.nonce).toBe('test-nonce-123'); // nonce
      expect(typeof decoded!.exp).toBe('number'); // expiration time
      expect(typeof decoded!.iat).toBe('number'); // issued at time
      
      // Verify exp is in the future and iat is reasonable
      const now = Math.floor(Date.now() / 1000);
      expect(decoded!.exp).toBeGreaterThan(now);
      expect(decoded!.iat).toBeLessThanOrEqual(now);
      expect(decoded!.iat).toBeGreaterThan(now - 60); // Within last minute
    });

    it('should generate access token in JWT format (Requirement 9.1)', () => {
      const token = jwtUtil.generateAccessToken({
        issuer: 'http://localhost:5173/oidc',
        clientId: 'test_client',
        userId: 'user123',
        expiresIn: 3600,
        scope: 'openid profile email'
      });

      // Verify JWT format (3 parts separated by dots)
      const parts = token.split('.');
      expect(parts).toHaveLength(3);
      
      // Verify each part is base64url encoded
      parts.forEach(part => {
        expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
      });

      // Verify token can be decoded and has correct structure
      const decoded = jwtUtil.decodeToken(token);
      expect(decoded).toBeTruthy();
      expect(decoded!.iss).toBe('http://localhost:5173/oidc');
      expect(decoded!.aud).toBe('test_client');
      expect(decoded!.sub).toBe('user123');
      expect(decoded!.client_id).toBe('test_client');
    });
  });

  describe('Algorithm Support (Requirement 9.4)', () => {
    it('should support HS256 algorithm with secret key', () => {
      const hsUtil = new JWTUtil({
        algorithm: 'HS256',
        secret: 'test-secret-key-256-bits-long'
      });

      const token = hsUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600
      });

      expect(token).toBeTruthy();
      expect(hsUtil.getAlgorithm()).toBe('HS256');

      // Verify token can be validated with same secret
      const result = hsUtil.validateToken(token);
      expect(result.valid).toBe(true);
    });

    it('should support configurable secret key', () => {
      const customSecret = 'my-custom-secret-key-for-development';
      const customUtil = new JWTUtil({
        algorithm: 'HS256',
        secret: customSecret
      });

      const token = customUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600
      });

      // Token should be valid with the custom secret
      const result = customUtil.validateToken(token);
      expect(result.valid).toBe(true);

      // But invalid with a different secret
      const differentUtil = new JWTUtil({
        algorithm: 'HS256',
        secret: 'different-secret'
      });
      const invalidResult = differentUtil.validateToken(token);
      expect(invalidResult.valid).toBe(false);
    });
  });

  describe('Signature Verification', () => {
    it('should verify token signature correctly', () => {
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600
      });

      // Valid signature should pass
      const validResult = jwtUtil.validateToken(token);
      expect(validResult.valid).toBe(true);
      expect(validResult.payload).toBeTruthy();
    });

    it('should reject token with tampered signature', () => {
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600
      });

      // Tamper with the signature (last part of JWT)
      const parts = token.split('.');
      const tamperedToken = parts[0] + '.' + parts[1] + '.tampered_signature';

      const result = jwtUtil.validateToken(tamperedToken);
      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });

    it('should reject token with tampered payload', () => {
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600
      });

      // Tamper with the payload (middle part of JWT)
      const parts = token.split('.');
      // Create a different payload
      const tamperedPayload = Buffer.from(JSON.stringify({
        iss: 'http://evil.com',
        aud: 'evil_client',
        sub: 'hacker',
        exp: Math.floor(Date.now() / 1000) + 3600
      })).toString('base64url');
      
      const tamperedToken = parts[0] + '.' + tamperedPayload + '.' + parts[2];

      const result = jwtUtil.validateToken(tamperedToken);
      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle token issued in future (clock skew)', () => {
      // Create a token that appears to be issued 2 minutes in the future
      const futureTime = Math.floor(Date.now() / 1000) + 120;
      const token = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: 3600,
        additionalClaims: {
          iat: futureTime
        }
      });

      const result = jwtUtil.validateToken(token);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('future');
    });

    it('should handle malformed JWT tokens', () => {
      const malformedTokens = [
        'not.a.jwt',
        'only.two.parts',
        'too.many.parts.here.extra',
        '',
        'single-string-no-dots'
      ];

      malformedTokens.forEach(token => {
        const result = jwtUtil.validateToken(token);
        expect(result.valid).toBe(false);
        expect(result.error).toBeTruthy();
      });
    });

    it('should provide specific error messages for different validation failures', () => {
      // Test expired token error message
      const expiredToken = jwtUtil.generateToken({
        issuer: 'http://localhost:5173/oidc',
        audience: 'test_client',
        subject: 'user123',
        expiresIn: -1
      });

      const expiredResult = jwtUtil.validateToken(expiredToken);
      expect(expiredResult.valid).toBe(false);
      expect(expiredResult.error).toContain('expired');

      // Test invalid signature error
      const invalidResult = jwtUtil.validateToken('invalid.jwt.token');
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.error).toBeTruthy();
    });
  });
});
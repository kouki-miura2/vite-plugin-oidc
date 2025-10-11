/**
 * Unit tests for ValidationUtil
 */

import { describe, it, expect } from 'vitest';
import { ValidationUtil } from "../../../src/utils/ValidationUtil.js";
import type { AuthorizationParams, TokenParams } from "../../../src/types/oidc.js";
import type { ClientConfig } from "../../../src/types/config.js";

describe('ValidationUtil', () => {
  const mockClients: ClientConfig[] = [
    {
      client_id: 'test_client',
      redirect_uris: ['https://example.com/callback', 'http://localhost:3000/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code']
    }
  ];

  describe('validateAuthorizationRequest', () => {
    const validAuthParams: AuthorizationParams = {
      client_id: 'test_client',
      redirect_uri: 'https://example.com/callback',
      response_type: 'code',
      code_challenge: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      code_challenge_method: 'S256',
      scope: 'openid profile',
      state: 'xyz',
      nonce: 'abc123'
    };

    it('should validate valid authorization request', () => {
      const result = ValidationUtil.validateAuthorizationRequest(validAuthParams, mockClients);
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should reject missing client_id', () => {
      const params = { ...validAuthParams, client_id: '' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('client_id');
    });

    it('should reject missing redirect_uri', () => {
      const params = { ...validAuthParams, redirect_uri: '' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('redirect_uri');
    });

    it('should reject missing response_type', () => {
      const params = { ...validAuthParams, response_type: '' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('response_type');
    });

    it('should reject missing code_challenge', () => {
      const params = { ...validAuthParams, code_challenge: '' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('code_challenge');
    });

    it('should reject missing code_challenge_method', () => {
      const params = { ...validAuthParams, code_challenge_method: '' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('code_challenge_method');
    });

    it('should reject unsupported response_type', () => {
      const params = { ...validAuthParams, response_type: 'token' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('unsupported_response_type');
    });

    it('should reject unsupported code_challenge_method', () => {
      const params = { ...validAuthParams, code_challenge_method: 'plain' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('S256');
    });

    it('should reject invalid client_id', () => {
      const params = { ...validAuthParams, client_id: 'invalid_client' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('unauthorized_client');
    });

    it('should reject unregistered redirect_uri', () => {
      const params = { ...validAuthParams, redirect_uri: 'https://evil.com/callback' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('not registered');
    });

    it('should reject invalid scope', () => {
      const params = { ...validAuthParams, scope: 'openid invalid_scope' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_scope');
    });

    it('should accept valid localhost redirect_uri with http', () => {
      const params = { ...validAuthParams, redirect_uri: 'http://localhost:3000/callback' };
      const result = ValidationUtil.validateAuthorizationRequest(params, mockClients);
      expect(result.isValid).toBe(true);
    });
  });

  describe('validateTokenRequest', () => {
    const validTokenParams: TokenParams = {
      grant_type: 'authorization_code',
      code: 'dGVzdF9hdXRob3JpemF0aW9uX2NvZGU',
      redirect_uri: 'https://example.com/callback',
      client_id: 'test_client',
      code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    };

    it('should validate valid token request', () => {
      const result = ValidationUtil.validateTokenRequest(validTokenParams, mockClients);
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should reject missing grant_type', () => {
      const params = { ...validTokenParams, grant_type: '' };
      const result = ValidationUtil.validateTokenRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('grant_type');
    });

    it('should reject unsupported grant_type', () => {
      const params = { ...validTokenParams, grant_type: 'client_credentials' };
      const result = ValidationUtil.validateTokenRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('unsupported_grant_type');
    });

    it('should reject missing code', () => {
      const params = { ...validTokenParams, code: '' };
      const result = ValidationUtil.validateTokenRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('code');
    });

    it('should reject missing client_id', () => {
      const params = { ...validTokenParams, client_id: '' };
      const result = ValidationUtil.validateTokenRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('client_id');
    });

    it('should reject missing code_verifier', () => {
      const params = { ...validTokenParams, code_verifier: '' };
      const result = ValidationUtil.validateTokenRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
      expect(result.error?.error_description).toContain('code_verifier');
    });

    it('should reject invalid client_id', () => {
      const params = { ...validTokenParams, client_id: 'invalid_client' };
      const result = ValidationUtil.validateTokenRequest(params, mockClients);
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_client');
    });
  });

  describe('validateScope', () => {
    it('should validate valid scope', () => {
      const result = ValidationUtil.validateScope('openid profile email');
      expect(result.isValid).toBe(true);
    });

    it('should reject empty scope', () => {
      const result = ValidationUtil.validateScope('');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_scope');
    });

    it('should reject unsupported scope', () => {
      const result = ValidationUtil.validateScope('openid invalid_scope');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_scope');
      expect(result.error?.error_description).toContain('invalid_scope');
    });

    it('should reject duplicate scopes', () => {
      const result = ValidationUtil.validateScope('openid profile openid');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('invalid_scope');
      expect(result.error?.error_description).toContain('Duplicate');
    });
  });

  describe('isValidRedirectUri', () => {
    it('should accept valid HTTPS URI', () => {
      expect(ValidationUtil.isValidRedirectUri('https://example.com/callback')).toBe(true);
    });

    it('should accept valid localhost HTTP URI', () => {
      expect(ValidationUtil.isValidRedirectUri('http://localhost:3000/callback')).toBe(true);
      expect(ValidationUtil.isValidRedirectUri('http://127.0.0.1:3000/callback')).toBe(true);
    });

    it('should reject HTTP URI for non-localhost', () => {
      expect(ValidationUtil.isValidRedirectUri('http://example.com/callback')).toBe(false);
    });

    it('should reject URI with fragment', () => {
      expect(ValidationUtil.isValidRedirectUri('https://example.com/callback#fragment')).toBe(false);
    });

    it('should reject invalid URI', () => {
      expect(ValidationUtil.isValidRedirectUri('not-a-uri')).toBe(false);
    });

    it('should reject non-HTTP(S) schemes', () => {
      expect(ValidationUtil.isValidRedirectUri('ftp://example.com/callback')).toBe(false);
    });
  });

  describe('isValidCodeChallenge', () => {
    it('should accept valid code challenge', () => {
      expect(ValidationUtil.isValidCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(true);
    });

    it('should accept test code challenge', () => {
      expect(ValidationUtil.isValidCodeChallenge('test_challenge')).toBe(true);
    });

    it('should reject too short code challenge', () => {
      expect(ValidationUtil.isValidCodeChallenge('short')).toBe(false);
    });

    it('should reject too long code challenge', () => {
      const longChallenge = 'a'.repeat(129);
      expect(ValidationUtil.isValidCodeChallenge(longChallenge)).toBe(false);
    });

    it('should reject invalid characters', () => {
      expect(ValidationUtil.isValidCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk+')).toBe(false);
    });
  });

  describe('isValidAccessToken', () => {
    it('should accept valid JWT token', () => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      expect(ValidationUtil.isValidAccessToken(token)).toBe(true);
    });

    it('should accept simple alphanumeric tokens for testing', () => {
      expect(ValidationUtil.isValidAccessToken('valid_token')).toBe(true);
      expect(ValidationUtil.isValidAccessToken('test-token-123')).toBe(true);
    });

    it('should reject invalid token formats', () => {
      expect(ValidationUtil.isValidAccessToken('invalid.token')).toBe(false);
      expect(ValidationUtil.isValidAccessToken('')).toBe(false);
      expect(ValidationUtil.isValidAccessToken('a')).toBe(false); // too short
    });
  });

  describe('getErrorStatusCode', () => {
    it('should return correct status codes', () => {
      expect(ValidationUtil.getErrorStatusCode('invalid_client')).toBe(401);
      expect(ValidationUtil.getErrorStatusCode('unauthorized_client')).toBe(401);
      expect(ValidationUtil.getErrorStatusCode('access_denied')).toBe(401);
      expect(ValidationUtil.getErrorStatusCode('invalid_request')).toBe(400);
      expect(ValidationUtil.getErrorStatusCode('server_error')).toBe(500);
      expect(ValidationUtil.getErrorStatusCode('temporarily_unavailable')).toBe(503);
      expect(ValidationUtil.getErrorStatusCode('unknown_error')).toBe(400);
    });
  });

  describe('createErrorResponse', () => {
    it('should create error response with all fields', () => {
      const error = ValidationUtil.createErrorResponse(
        'invalid_request',
        'Missing parameter',
        'https://example.com/error',
        'xyz'
      );

      expect(error.error).toBe('invalid_request');
      expect(error.error_description).toBe('Missing parameter');
      expect(error.error_uri).toBe('https://example.com/error');
      expect(error.state).toBe('xyz');
    });

    it('should create error response with minimal fields', () => {
      const error = ValidationUtil.createErrorResponse('invalid_request');
      expect(error.error).toBe('invalid_request');
      expect(error.error_description).toBeUndefined();
      expect(error.error_uri).toBeUndefined();
      expect(error.state).toBeUndefined();
    });
  });
});
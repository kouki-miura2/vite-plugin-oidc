/**
 * Tests for TokenHandler
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { TokenHandler } from '../../../src/handlers/TokenHandler.js'
import { InMemoryStore } from '../../../src/storage/InMemoryStore.js'
import { TokenService } from '../../../src/services/TokenService.js'
import type { Request, Response } from '../../../src/types/handlers.js'
import type {
  UserAccount,
  ClientConfig,
  OIDCPluginConfig,
  JWTConfig,
} from '../../../src/types/index.js'

describe('TokenHandler', () => {
  let tokenHandler: TokenHandler
  let store: InMemoryStore
  let tokenService: TokenService
  let mockResponse: Response

  const testConfig: OIDCPluginConfig = {
    basePath: '/oidc',
    issuer: 'http://localhost:5173/oidc',
  }

  const jwtConfig: JWTConfig = {
    algorithm: 'HS256',
    secret: 'test-secret-key',
  }

  const testUsers: UserAccount[] = [
    {
      id: '1',
      username: 'testuser',
      password: 'password123',
      profile: {
        sub: '1',
        name: 'Test User',
        email: 'test@example.com',
        email_verified: true,
      },
    },
  ]

  const testClients: ClientConfig[] = [
    {
      client_id: 'test_client',
      redirect_uris: ['http://localhost:3000/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code'],
    },
  ]

  beforeEach(() => {
    store = new InMemoryStore()
    const tokenExpiration: any = {} // provide defaults for tests
    const basePath = '/oidc'
    tokenService = new TokenService(
      jwtConfig,
      testConfig.issuer!,
      tokenExpiration,
      basePath,
    )
    tokenHandler = new TokenHandler(
      store,
      testConfig,
      testUsers,
      testClients,
      tokenService,
    )

    // Mock response object
    mockResponse = {
      statusCode: 200,
      setHeader: vi.fn(),
      end: vi.fn(),
    }
  })

  describe('validateTokenRequest', () => {
    it('should validate a correct token request', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(true)
    })

    it('should reject request with missing grant_type', () => {
      const params = {
        grant_type: '',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_request')
      expect(result.error?.error_description).toContain('grant_type')
    })

    it('should reject request with missing code', () => {
      const params = {
        grant_type: 'authorization_code',
        code: '',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_request')
      expect(result.error?.error_description).toContain('code')
    })

    it('should reject request with missing client_id', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: '',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_request')
      expect(result.error?.error_description).toContain('client_id')
    })

    it('should reject request with missing redirect_uri', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: '',
        client_id: 'test_client',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_request')
      expect(result.error?.error_description).toContain('redirect_uri')
    })

    it('should reject request with invalid client_id', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'invalid_client',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_client')
    })

    it('should reject request with invalid redirect_uri', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://invalid-domain.com/callback',
        client_id: 'test_client',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_request')
      expect(result.error?.error_description).toContain('redirect_uri')
    })

    it('should reject request with unsupported grant_type', () => {
      const params = {
        grant_type: 'client_credentials',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('unsupported_grant_type')
    })

    it('should reject request with missing code_verifier', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: '',
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_request')
      expect(result.error?.error_description).toContain('code_verifier')
    })

    it('should reject request with invalid code_verifier format', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: 'invalid@verifier#with$special%chars', // Invalid characters
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_request')
      expect(result.error?.error_description).toContain('code_verifier format')
    })

    it('should reject request with code_verifier that is too short', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: 'short', // Too short (< 43 characters)
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(false)
      expect(result.error?.error).toBe('invalid_request')
      expect(result.error?.error_description).toContain('code_verifier format')
    })

    it('should accept valid code_verifier with minimum length', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: 'a'.repeat(43), // Minimum valid length
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(true)
    })

    it('should accept valid code_verifier with maximum length', () => {
      const params = {
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        code_verifier: 'a'.repeat(128), // Maximum valid length
      }

      const result = tokenHandler.validateTokenRequest(params)
      expect(result.isValid).toBe(true)
    })
  })

  describe('exchangeCodeForTokens', () => {
    it('should exchange valid authorization code for tokens', () => {
      // Store a test authorization code
      const authCode = {
        code: 'test_auth_code',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      const result = tokenHandler.exchangeCodeForTokens(
        'test_auth_code',
        codeVerifier,
      )

      expect(result.access_token).toBeDefined()
      expect(result.token_type).toBe('Bearer')
      expect(result.expires_in).toBe(3600)
      expect(result.id_token).toBeDefined() // Should have ID token for openid scope
    })

    it('should throw error for invalid authorization code', () => {
      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

      expect(() => {
        tokenHandler.exchangeCodeForTokens('invalid_code', codeVerifier)
      }).toThrow('Invalid authorization code')
    })

    it('should throw error for invalid code verifier', () => {
      // Store a test authorization code
      const authCode = {
        code: 'test_auth_code',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      const invalidCodeVerifier = 'invalid_verifier'

      expect(() => {
        tokenHandler.exchangeCodeForTokens(
          'test_auth_code',
          invalidCodeVerifier,
        )
      }).toThrow('Invalid code verifier')
    })

    it('should validate PKCE code challenge correctly', () => {
      // Test with known code verifier and challenge pair
      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      const codeChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

      const authCode = {
        code: 'pkce_test_code',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: codeChallenge,
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      const result = tokenHandler.exchangeCodeForTokens(
        'pkce_test_code',
        codeVerifier,
      )

      expect(result.access_token).toBeDefined()
      expect(result.token_type).toBe('Bearer')
      expect(result.expires_in).toBe(3600)

      // Verify the authorization code is deleted after use
      const deletedCode = store.getAuthorizationCode('pkce_test_code')
      expect(deletedCode).toBeNull()
    })

    it('should fail PKCE validation with wrong code verifier', () => {
      const correctCodeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      const correctCodeChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
      const wrongCodeVerifier = 'wrong_code_verifier_that_wont_match_challenge'

      const authCode = {
        code: 'pkce_fail_test',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: correctCodeChallenge,
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      expect(() => {
        tokenHandler.exchangeCodeForTokens('pkce_fail_test', wrongCodeVerifier)
      }).toThrow('Invalid code verifier')
    })

    it('should handle expired authorization codes', () => {
      // Store an expired authorization code
      const expiredAuthCode = {
        code: 'expired_code',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() - 1000, // Expired 1 second ago
      }
      store.storeAuthorizationCode(expiredAuthCode)

      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

      // The store automatically removes expired codes, so this should throw an error
      expect(() => {
        tokenHandler.exchangeCodeForTokens('expired_code', codeVerifier)
      }).toThrow('Invalid authorization code')
    })

    it('should throw error when user is not found', () => {
      // Store authorization code with non-existent user
      const authCode = {
        code: 'no_user_code',
        clientId: 'test_client',
        userId: 'non_existent_user',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

      expect(() => {
        tokenHandler.exchangeCodeForTokens('no_user_code', codeVerifier)
      }).toThrow('User not found')
    })

    it('should store access token after successful exchange', () => {
      const authCode = {
        code: 'store_token_test',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: 'openid profile email',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      const result = tokenHandler.exchangeCodeForTokens(
        'store_token_test',
        codeVerifier,
      )

      // Verify the access token is stored
      const storedToken = store.getAccessToken(result.access_token)
      expect(storedToken).toBeDefined()
      expect(storedToken?.userId).toBe('1')
      expect(storedToken?.clientId).toBe('test_client')
      expect(storedToken?.scope).toBe('openid profile email')
    })

    it('should generate tokens with correct scope and nonce', () => {
      const testNonce = 'test_nonce_12345'
      const testScope = 'openid profile email'

      const authCode = {
        code: 'scope_nonce_test',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: testScope,
        nonce: testNonce,
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      const result = tokenHandler.exchangeCodeForTokens(
        'scope_nonce_test',
        codeVerifier,
      )

      expect(result.access_token).toBeDefined()
      expect(result.id_token).toBeDefined()
      expect(result.scope).toBe(testScope)

      // The nonce should be included in the ID token (verified by TokenService)
      expect(result.id_token).toBeTruthy()
    })
  })

  describe('handleToken', () => {
    it('should reject non-POST requests', async () => {
      const request: Request = {
        method: 'GET',
        headers: {},
        body: '',
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(400)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )
      expect(mockResponse.end).toHaveBeenCalledWith(
        expect.stringContaining('invalid_request'),
      )
    })

    it('should successfully exchange authorization code for tokens', async () => {
      // Store a valid authorization code
      const authCode = {
        code: 'valid_auth_code',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=valid_auth_code&redirect_uri=http://localhost:3000/callback&client_id=test_client&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(200)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Cache-Control',
        'no-store',
      )
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Pragma', 'no-cache')

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.access_token).toBeDefined()
      expect(responseBody.token_type).toBe('Bearer')
      expect(responseBody.expires_in).toBe(3600)
      expect(responseBody.id_token).toBeDefined()
    })

    it('should return invalid_grant for invalid authorization code', async () => {
      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=invalid_code&redirect_uri=http://localhost:3000/callback&client_id=test_client&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(400)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.error).toBe('invalid_grant')
      expect(responseBody.error_description).toContain(
        'Invalid authorization code',
      )
    })

    it('should return invalid_grant for invalid code verifier', async () => {
      // Store a valid authorization code
      const authCode = {
        code: 'valid_code_invalid_verifier',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      // Use a valid format but wrong verifier that will pass validation but fail PKCE
      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=valid_code_invalid_verifier&redirect_uri=http://localhost:3000/callback&client_id=test_client&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_wrong',
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(400)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.error).toBe('invalid_grant')
      expect(responseBody.error_description).toContain(
        'Invalid authorization code or code verifier',
      )
    })

    it('should return invalid_client for invalid client_id', async () => {
      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=test_code&redirect_uri=http://localhost:3000/callback&client_id=invalid_client&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(401)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.error).toBe('invalid_client')
    })

    it('should return unsupported_grant_type for non-authorization_code grant', async () => {
      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=client_credentials&code=test_code&redirect_uri=http://localhost:3000/callback&client_id=test_client&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(400)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.error).toBe('unsupported_grant_type')
    })

    it('should return invalid_request for missing required parameters', async () => {
      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code', // Missing other required parameters
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(400)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.error).toBe('invalid_request')
    })

    it('should return invalid_request for invalid redirect_uri', async () => {
      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=test_code&redirect_uri=http://malicious-site.com/callback&client_id=test_client&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(400)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.error).toBe('invalid_request')
      expect(responseBody.error_description).toContain('redirect_uri')
    })

    it('should handle server errors gracefully', async () => {
      // Mock the parseFormBody method to throw an error
      const originalParseFormBody = (tokenHandler as any).parseFormBody
      ;(tokenHandler as any).parseFormBody = vi.fn().mockImplementation(() => {
        throw new Error('Parsing error')
      })

      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=test&redirect_uri=http://localhost:3000/callback&client_id=test_client&code_verifier=test',
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(500)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.error).toBe('server_error')

      // Restore the original method
      ;(tokenHandler as any).parseFormBody = originalParseFormBody
    })

    it('should handle object-based request body', async () => {
      // Store a valid authorization code
      const authCode = {
        code: 'object_body_test',
        clientId: 'test_client',
        userId: '1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        expiresAt: Date.now() + 600000,
      }
      store.storeAuthorizationCode(authCode)

      const request: Request = {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: {
          grant_type: 'authorization_code',
          code: 'object_body_test',
          redirect_uri: 'http://localhost:3000/callback',
          client_id: 'test_client',
          code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        },
      }

      await tokenHandler.handleToken(request, mockResponse)

      expect(mockResponse.statusCode).toBe(200)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )

      const responseBody = JSON.parse(
        (mockResponse.end as any).mock.calls[0][0],
      )
      expect(responseBody.access_token).toBeDefined()
      expect(responseBody.token_type).toBe('Bearer')
    })
  })
})

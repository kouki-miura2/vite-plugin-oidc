/**
 * Unit tests for UserInfoHandler
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { UserInfoHandler } from '../../../src/handlers/UserInfoHandler.js'
import type { InMemoryStore, AccessToken } from '../../../src/types/storage.js'
import type {
  UserAccount,
  OIDCPluginConfig,
} from '../../../src/types/config.js'
import type { Request, Response } from '../../../src/types/handlers.js'
import { TokenService } from '../../../src/services/TokenService.js'

// Mock TokenService
vi.mock('../services/TokenService.js')

describe('UserInfoHandler', () => {
  let handler: UserInfoHandler
  let mockStore: InMemoryStore
  let mockTokenService: TokenService
  let mockResponse: Response
  let testUsers: UserAccount[]
  let config: OIDCPluginConfig

  beforeEach(() => {
    // Setup test users
    testUsers = [
      {
        id: '1',
        username: 'testuser',
        password: 'password',
        profile: {
          sub: '1',
          name: 'Test User',
          given_name: 'Test',
          family_name: 'User',
          email: 'test@example.com',
          email_verified: true,
          picture: 'https://example.com/avatar.jpg',
          locale: 'en-US',
          role: 'user',
        },
      },
      {
        id: '2',
        username: 'admin',
        password: 'admin123',
        profile: {
          sub: '2',
          name: 'Admin User',
          email: 'admin@example.com',
          email_verified: true,
          role: 'admin',
        },
      },
    ]

    // Setup config
    config = {
      basePath: '/oidc',
      issuer: 'http://localhost:5173/oidc',
    }

    // Mock store
    mockStore = {
      storeAuthorizationCode: vi.fn(),
      getAuthorizationCode: vi.fn(),
      deleteAuthorizationCode: vi.fn(),
      storeAccessToken: vi.fn(),
      getAccessToken: vi.fn(),
      deleteAccessToken: vi.fn(),
      storeSession: vi.fn(),
      getSession: vi.fn(),
      deleteSession: vi.fn(),
      cleanup: vi.fn(),
    }

    // Mock TokenService
    mockTokenService = {
      validateAccessToken: vi.fn(),
    } as unknown as TokenService

    // Mock response
    mockResponse = {
      statusCode: 200,
      setHeader: vi.fn(),
      end: vi.fn(),
    }

    handler = new UserInfoHandler(
      mockStore,
      config,
      testUsers,
      mockTokenService,
    )
  })

  describe('handleUserInfo', () => {
    it('should return 405 for non-GET requests', async () => {
      const request: Request = {
        method: 'POST',
        headers: {},
      }

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(405)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'invalid_request',
          error_description: 'UserInfo endpoint only accepts GET requests',
        }),
      )
    })

    it('should return 401 when Authorization header is missing', async () => {
      const request: Request = {
        method: 'GET',
        headers: {},
      }

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(401)
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'WWW-Authenticate',
        'Bearer',
      )
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'invalid_token',
          error_description: 'Missing Authorization header',
        }),
      )
    })

    it('should return 401 when Authorization header format is invalid', async () => {
      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'InvalidFormat token123',
        },
      }

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(401)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'invalid_token',
          error_description:
            'Invalid Authorization header format. Expected: Bearer <token>',
        }),
      )
    })

    it('should return 401 when access token is invalid', async () => {
      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer invalid_token',
        },
      }

      // Mock token not found in store
      vi.mocked(mockStore.getAccessToken).mockReturnValue(null)

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(401)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'invalid_token',
          error_description: 'Token not found in store',
        }),
      )
    })

    it('should return 401 when access token is expired', async () => {
      const expiredToken: AccessToken = {
        token: 'expired_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid profile email',
        expiresAt: Date.now() - 1000, // Expired 1 second ago
      }

      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer expired_token',
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(expiredToken)

      await handler.handleUserInfo(request, mockResponse)

      expect(mockStore.deleteAccessToken).toHaveBeenCalledWith('expired_token')
      expect(mockResponse.statusCode).toBe(401)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'invalid_token',
          error_description: 'Token has expired',
        }),
      )
    })

    it('should return user info when access token is valid', async () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid profile email',
        expiresAt: Date.now() + 3600000, // Expires in 1 hour
      }

      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer valid_token',
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '1', iss: 'http://localhost:5173/oidc' },
      })

      await handler.handleUserInfo(request, mockResponse)

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

      const expectedUserInfo = {
        sub: '1',
        name: 'Test User',
        given_name: 'Test',
        family_name: 'User',
        picture: 'https://example.com/avatar.jpg',
        locale: 'en-US',
        email: 'test@example.com',
        email_verified: true,
        role: 'user',
      }

      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify(expectedUserInfo),
      )
    })

    it('should filter user info based on scope', async () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid profile', // No email scope
        expiresAt: Date.now() + 3600000,
      }

      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer valid_token',
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '1', iss: 'http://localhost:5173/oidc' },
      })

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(200)

      const expectedUserInfo = {
        sub: '1',
        name: 'Test User',
        given_name: 'Test',
        family_name: 'User',
        picture: 'https://example.com/avatar.jpg',
        locale: 'en-US',
        role: 'user',
        // Note: email and email_verified should not be included
      }

      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify(expectedUserInfo),
      )
    })

    it('should return minimal info when no scope is provided', async () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: undefined,
        expiresAt: Date.now() + 3600000,
      }

      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer valid_token',
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '1', iss: 'http://localhost:5173/oidc' },
      })

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(200)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({ sub: '1' }),
      )
    })

    it('should return 401 when user is not found', async () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '999', // Non-existent user
        clientId: 'test_client',
        scope: 'openid profile email',
        expiresAt: Date.now() + 3600000,
      }

      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer valid_token',
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '999', iss: 'http://localhost:5173/oidc' },
      })

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(401)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'invalid_token',
          error_description: 'User not found',
        }),
      )
    })

    it('should handle Authorization header with different casing', async () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid profile email',
        expiresAt: Date.now() + 3600000,
      }

      const request: Request = {
        method: 'GET',
        headers: {
          Authorization: 'Bearer valid_token', // Capital A
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '1', iss: 'http://localhost:5173/oidc' },
      })

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(200)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          sub: '1',
          name: 'Test User',
          given_name: 'Test',
          family_name: 'User',
          picture: 'https://example.com/avatar.jpg',
          locale: 'en-US',
          email: 'test@example.com',
          email_verified: true,
          role: 'user',
        }),
      )
    })

    it('should handle Bearer token with different casing', async () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid profile email',
        expiresAt: Date.now() + 3600000,
      }

      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'bearer valid_token', // lowercase bearer
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '1', iss: 'http://localhost:5173/oidc' },
      })

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(200)
    })

    it('should return 401 when JWT validation fails without error message', async () => {
      const validToken: AccessToken = {
        token: 'invalid_jwt_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid',
        expiresAt: Date.now() + 3600000,
      }

      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer invalid_jwt_token',
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: false,
        // No error message provided
      })

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(401)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'invalid_token',
          error_description: 'Invalid token signature or claims',
        }),
      )
    })

    it('should return 500 when an unexpected error occurs during processing', async () => {
      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer valid_token',
        },
      }

      // Create a new mock response for this test to avoid interference
      const errorMockResponse = {
        statusCode: 200,
        setHeader: vi.fn(),
        end: vi.fn(),
      }

      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid profile email',
        expiresAt: Date.now() + 3600000,
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '1', iss: 'http://localhost:5173/oidc' },
      })

      // Mock JSON.stringify to throw an error during user info serialization
      const originalStringify = JSON.stringify
      vi.spyOn(JSON, 'stringify').mockImplementation((value) => {
        if (value && typeof value === 'object' && value.sub === '1') {
          throw new Error('JSON serialization failed')
        }
        return originalStringify(value)
      })

      await handler.handleUserInfo(request, errorMockResponse)

      expect(errorMockResponse.statusCode).toBe(500)
      expect(errorMockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'server_error',
          error_description: 'Internal server error',
        }),
      )

      // Restore original JSON.stringify
      vi.restoreAllMocks()
    })

    it('should include only email scope claims when only email scope is provided', async () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid email', // Only email scope, no profile
        expiresAt: Date.now() + 3600000,
      }

      const request: Request = {
        method: 'GET',
        headers: {
          authorization: 'Bearer valid_token',
        },
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '1', iss: 'http://localhost:5173/oidc' },
      })

      await handler.handleUserInfo(request, mockResponse)

      expect(mockResponse.statusCode).toBe(200)

      const expectedUserInfo = {
        sub: '1',
        email: 'test@example.com',
        email_verified: true,
        role: 'user', // Custom claims are always included
      }

      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify(expectedUserInfo),
      )
    })
  })

  describe('validateAccessToken', () => {
    it('should return invalid when token is not found in store', () => {
      vi.mocked(mockStore.getAccessToken).mockReturnValue(null)

      const result = handler.validateAccessToken('nonexistent_token')

      expect(result.isValid).toBe(false)
      expect(result.error).toBe('Token not found in store')
    })

    it('should return invalid and cleanup when token is expired', () => {
      const expiredToken: AccessToken = {
        token: 'expired_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid',
        expiresAt: Date.now() - 1000,
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(expiredToken)

      const result = handler.validateAccessToken('expired_token')

      expect(result.isValid).toBe(false)
      expect(result.error).toBe('Token has expired')
      expect(mockStore.deleteAccessToken).toHaveBeenCalledWith('expired_token')
    })

    it('should return invalid when JWT validation fails', () => {
      const validToken: AccessToken = {
        token: 'invalid_jwt_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid',
        expiresAt: Date.now() + 3600000,
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: false,
        error: 'Invalid signature',
      })

      const result = handler.validateAccessToken('invalid_jwt_token')

      expect(result.isValid).toBe(false)
      expect(result.error).toBe('Invalid signature')
    })

    it('should return valid with token details when validation succeeds', () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid profile email',
        expiresAt: Date.now() + 3600000,
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockReturnValue({
        valid: true,
        payload: { sub: '1', iss: 'http://localhost:5173/oidc' },
      })

      const result = handler.validateAccessToken('valid_token')

      expect(result.isValid).toBe(true)
      expect(result.userId).toBe('1')
      expect(result.clientId).toBe('test_client')
      expect(result.scope).toBe('openid profile email')
    })

    it('should handle token validation exception gracefully', () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid',
        expiresAt: Date.now() + 3600000,
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockImplementation(() => {
        throw new Error('JWT parsing failed')
      })

      const result = handler.validateAccessToken('valid_token')

      expect(result.isValid).toBe(false)
      expect(result.error).toBe('Token validation error: JWT parsing failed')
    })

    it('should handle non-Error exceptions in token validation', () => {
      const validToken: AccessToken = {
        token: 'valid_token',
        userId: '1',
        clientId: 'test_client',
        scope: 'openid',
        expiresAt: Date.now() + 3600000,
      }

      vi.mocked(mockStore.getAccessToken).mockReturnValue(validToken)
      vi.mocked(mockTokenService.validateAccessToken).mockImplementation(() => {
        throw 'String error' // Non-Error exception
      })

      const result = handler.validateAccessToken('valid_token')

      expect(result.isValid).toBe(false)
      expect(result.error).toBe('Token validation error: Unknown error')
    })
  })

  describe('getUserInfo', () => {
    it('should return user profile when user exists', () => {
      const userInfo = handler.getUserInfo('1')

      expect(userInfo).toEqual({
        sub: '1',
        name: 'Test User',
        given_name: 'Test',
        family_name: 'User',
        email: 'test@example.com',
        email_verified: true,
        picture: 'https://example.com/avatar.jpg',
        locale: 'en-US',
        role: 'user',
      })
    })

    it('should return null when user does not exist', () => {
      const userInfo = handler.getUserInfo('999')

      expect(userInfo).toBeNull()
    })

    it('should return a copy of user profile to avoid mutations', () => {
      const userInfo1 = handler.getUserInfo('1')
      const userInfo2 = handler.getUserInfo('1')

      expect(userInfo1).toEqual(userInfo2)
      expect(userInfo1).not.toBe(userInfo2) // Different object references
    })

    it('should handle user with minimal profile information', () => {
      const userInfo = handler.getUserInfo('2') // Admin user with minimal profile

      expect(userInfo).toEqual({
        sub: '2',
        name: 'Admin User',
        email: 'admin@example.com',
        email_verified: true,
        role: 'admin',
      })
    })
  })
})

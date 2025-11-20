/**
 * Unit tests for DiscoveryHandler
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { DiscoveryHandler } from '../../../src/handlers/DiscoveryHandler.js'
import type { OIDCPluginConfig } from '../../../src/types/config.js'
import type { Request, Response } from '../../../src/types/handlers.js'
import { ENDPOINTS, SUPPORTED } from '../../../src/constants.js'

describe('DiscoveryHandler', () => {
  let handler: DiscoveryHandler
  let mockConfig: OIDCPluginConfig
  let mockRequest: Request
  let mockResponse: Response

  beforeEach(() => {
    mockConfig = {
      basePath: '/oidc',
      jwt: {
        algorithm: 'HS256',
        secret: 'test-secret',
      },
      development: {
        enableLogging: false,
      },
    }

    handler = new DiscoveryHandler(mockConfig, 'http://localhost:5173/oidc')

    mockRequest = {
      url: '/.well-known/openid-configuration',
      method: 'GET',
      headers: {},
      query: {},
    }

    mockResponse = {
      statusCode: 200,
      setHeader: vi.fn(),
      end: vi.fn(),
    }
  })

  describe('generateDiscoveryDocument', () => {
    it('should generate a valid OIDC discovery document', () => {
      const document = handler.generateDiscoveryDocument()

      expect(document).toEqual({
        issuer: 'http://localhost:5173/oidc',
        authorization_endpoint: 'http://localhost:5173/oidc/authorize',
        token_endpoint: 'http://localhost:5173/oidc/token',
        userinfo_endpoint: 'http://localhost:5173/oidc/userinfo',
        jwks_uri: 'http://localhost:5173/oidc/jwks',
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256'],
        scopes_supported: ['openid', 'profile', 'email'],
        claims_supported: ['sub', 'name', 'email', 'email_verified'],
        token_endpoint_auth_methods_supported: ['none'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['HS256'],
        response_modes_supported: ['query'],
        end_session_endpoint: 'http://localhost:5173/oidc/logout',
        claims_parameter_supported: false,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
      })
    })

    it('should handle different JWT algorithms', () => {
      const rsaConfig = {
        ...mockConfig,
        jwt: {
          algorithm: 'RS256' as const,
          privateKey: 'test-private-key',
          publicKey: 'test-public-key',
        },
      }

      const rsaHandler = new DiscoveryHandler(
        rsaConfig,
        'http://localhost:5173/oidc',
      )
      const document = rsaHandler.generateDiscoveryDocument()

      expect(document.id_token_signing_alg_values_supported).toEqual(['RS256'])
    })

    it('should handle custom base path', () => {
      const customConfig = {
        ...mockConfig,
        basePath: '/auth',
      }

      const customHandler = new DiscoveryHandler(
        customConfig,
        'http://localhost:5173/auth',
      )
      const document = customHandler.generateDiscoveryDocument()

      expect(document.authorization_endpoint).toBe(
        'http://localhost:5173/auth/authorize',
      )
      expect(document.token_endpoint).toBe('http://localhost:5173/auth/token')
      expect(document.userinfo_endpoint).toBe(
        'http://localhost:5173/auth/userinfo',
      )
      expect(document.jwks_uri).toBe('http://localhost:5173/auth/jwks')
    })

    it('should handle issuer without base path', () => {
      const handler = new DiscoveryHandler(mockConfig, 'http://localhost:5173')
      const document = handler.generateDiscoveryDocument()

      expect(document.issuer).toBe('http://localhost:5173')
      expect(document.authorization_endpoint).toBe(
        'http://localhost:5173/oidc/authorize',
      )
    })
  })

  describe('handleDiscovery', () => {
    it('should serve discovery document successfully', async () => {
      await handler.handleDiscovery(mockRequest, mockResponse)

      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Cache-Control',
        'public, max-age=3600',
      )
      expect(mockResponse.statusCode).toBe(200)
      expect(mockResponse.end).toHaveBeenCalledWith(
        expect.stringContaining('"issuer": "http://localhost:5173/oidc"'),
      )
    })

    it('should handle errors gracefully', async () => {
      // Mock generateDiscoveryDocument to throw an error
      vi.spyOn(handler, 'generateDiscoveryDocument').mockImplementation(() => {
        throw new Error('Test error')
      })

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      await handler.handleDiscovery(mockRequest, mockResponse)

      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json',
      )
      expect(mockResponse.statusCode).toBe(500)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'server_error',
          error_description:
            'Internal server error while generating discovery document',
        }),
      )
      expect(consoleSpy).toHaveBeenCalled()

      consoleSpy.mockRestore()
    })

    it('should log when logging is enabled', async () => {
      const loggingConfig = {
        ...mockConfig,
        development: {
          enableLogging: true,
        },
      }

      const loggingHandler = new DiscoveryHandler(
        loggingConfig,
        'http://localhost:5173/oidc',
      )
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      await loggingHandler.handleDiscovery(mockRequest, mockResponse)

      expect(consoleSpy).toHaveBeenCalledWith(
        '[OIDC Discovery] Discovery document served',
      )

      consoleSpy.mockRestore()
    })
  })

  describe('utility methods', () => {
    it('should return correct issuer', () => {
      expect(handler.getIssuer()).toBe('http://localhost:5173/oidc')
    })

    it('should return correct base path', () => {
      expect(handler.getBasePath()).toBe('/oidc')
    })
  })
})

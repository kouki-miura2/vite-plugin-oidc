/**
 * Unit tests for JWKSHandler
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { JWKSHandler } from '../../../src/handlers/JWKSHandler.js'
import type { OIDCPluginConfig } from '../../../src/types/config.js'
import type { Request, Response } from '../../../src/types/handlers.js'

describe('JWKSHandler', () => {
  let handler: JWKSHandler
  let mockConfig: OIDCPluginConfig
  let mockRequest: Request
  let mockResponse: Response

  beforeEach(() => {
    mockConfig = {
      basePath: '/oidc',
      jwt: {
        algorithm: 'HS256',
        secret: 'test-secret-key',
      },
      development: {
        enableLogging: false,
      },
    }

    handler = new JWKSHandler(mockConfig)

    mockRequest = {
      url: '/jwks',
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

  describe('generateJWKS', () => {
    it('should generate JWKS for HS256 algorithm', () => {
      const jwks = handler.generateJWKS()

      expect(jwks.keys).toHaveLength(1)
      expect(jwks.keys[0]).toMatchObject({
        kty: 'oct',
        use: 'sig',
        alg: 'HS256',
        kid: expect.stringMatching(/^hs256-[a-f0-9]{8}$/),
        k: expect.any(String),
      })
    })

    it('should generate JWKS for RS256 algorithm', () => {
      // Mock RSA key pair for testing
      const mockPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf+FxKlaXkl9gvWKKVBdkmKdKHrAK50cINhw8kDd
VYoun1hG2jOQBzTufN9hXjMqZeFKiNFNNlHwZn2B7QOjNh0RbDbGaPWnX7sapSiQ
7UeVswirQoKr+1JJ2LJdiqcCtJoNrI0R2BfzAVCh9lJj2yBXw8K2yWKaEZsQhgef
DcQRP6Do9og2h6RNhcNjrQdVw/XlRNmEiCszbemFBMCAwVttfuZq0mMTrMaaklep
mgTOAiB6xz9KluD9MjOQKu8dHnU/b3p8ZjmqDOuKHtcKNe1jS2aqr2jidAn51QIDAQAB
-----END PUBLIC KEY-----`

      const rsaConfig = {
        ...mockConfig,
        jwt: {
          algorithm: 'RS256' as const,
          privateKey: 'mock-private-key',
          publicKey: mockPublicKey,
        },
      }

      const rsaHandler = new JWKSHandler(rsaConfig)

      // Mock the crypto operations since we're testing with a real key
      const mockExtractComponents = vi
        .spyOn(rsaHandler as any, 'extractRSAPublicKeyComponents')
        .mockReturnValue({
          n: 'mock-n-value',
          e: 'AQAB',
        })

      const jwks = rsaHandler.generateJWKS()

      expect(jwks.keys).toHaveLength(1)
      expect(jwks.keys[0]).toMatchObject({
        kty: 'RSA',
        use: 'sig',
        alg: 'RS256',
        kid: expect.stringMatching(/^rs256-[a-f0-9]{8}$/),
        n: 'mock-n-value',
        e: 'AQAB',
      })

      mockExtractComponents.mockRestore()
    })

    it('should cache JWKS document', () => {
      const jwks1 = handler.generateJWKS()
      const jwks2 = handler.generateJWKS()

      expect(jwks1).toBe(jwks2) // Same object reference
    })

    it('should clear cache when requested', () => {
      const jwks1 = handler.generateJWKS()
      handler.clearCache()
      const jwks2 = handler.generateJWKS()

      expect(jwks1).not.toBe(jwks2) // Different object references
      // Content should be similar structure but key IDs will be different due to timestamp
      expect(jwks1.keys).toHaveLength(jwks2.keys.length)
      expect(jwks1.keys[0].kty).toBe(jwks2.keys[0].kty)
      expect(jwks1.keys[0].alg).toBe(jwks2.keys[0].alg)
      expect(jwks1.keys[0].use).toBe(jwks2.keys[0].use)
      expect(jwks1.keys[0].k).toBe(jwks2.keys[0].k) // Same secret, same base64 encoding
    })

    it('should show warning for HS256 in development', () => {
      const warningConfig = {
        ...mockConfig,
        development: {
          enableLogging: false,
        },
      }

      const warningHandler = new JWKSHandler(warningConfig)
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      warningHandler.generateJWKS()

      expect(consoleSpy).toHaveBeenCalledWith(
        '[OIDC JWKS] Warning: Exposing symmetric key in JWKS is for development only!'
      )

      consoleSpy.mockRestore()
    })

    it('should throw error for RS256 without public key', () => {
      const invalidConfig = {
        ...mockConfig,
        jwt: {
          algorithm: 'RS256' as const,
          privateKey: 'test-private-key',
          // Missing publicKey
        },
      }

      const invalidHandler = new JWKSHandler(invalidConfig)

      expect(() => invalidHandler.generateJWKS()).toThrow(
        'Public key is required for RS256 algorithm'
      )
    })
  })

  describe('handleJWKS', () => {
    it('should serve JWKS document successfully', async () => {
      await handler.handleJWKS(mockRequest, mockResponse)

      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json'
      )
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Cache-Control',
        'public, max-age=86400'
      )
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      )
      expect(mockResponse.statusCode).toBe(200)
      expect(mockResponse.end).toHaveBeenCalledWith(
        expect.stringContaining('"keys"')
      )
    })

    it('should handle errors gracefully', async () => {
      // Mock generateJWKS to throw an error
      vi.spyOn(handler, 'generateJWKS').mockImplementation(() => {
        throw new Error('Test error')
      })

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      await handler.handleJWKS(mockRequest, mockResponse)

      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'application/json'
      )
      expect(mockResponse.statusCode).toBe(500)
      expect(mockResponse.end).toHaveBeenCalledWith(
        JSON.stringify({
          error: 'server_error',
          error_description:
            'Internal server error while generating JWKS document',
        })
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

      const loggingHandler = new JWKSHandler(loggingConfig)
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      await loggingHandler.handleJWKS(mockRequest, mockResponse)

      expect(consoleSpy).toHaveBeenCalledWith(
        '[OIDC JWKS] JWKS document served'
      )

      consoleSpy.mockRestore()
    })
  })

  describe('utility methods', () => {
    it('should return correct algorithm', () => {
      expect(handler.getAlgorithm()).toBe('HS256')
    })

    it('should return default algorithm when not specified', () => {
      const defaultHandler = new JWKSHandler({})
      expect(defaultHandler.getAlgorithm()).toBe('HS256')
    })
  })

  describe('base64UrlEncode', () => {
    it('should encode buffer to base64url format', () => {
      const buffer = Buffer.from('test-string', 'utf8')
      const encoded = (handler as any).base64UrlEncode(buffer)

      // Base64URL should not contain +, /, or = characters
      expect(encoded).not.toMatch(/[+/=]/)
      expect(typeof encoded).toBe('string')
    })
  })

  describe('generateKeyId', () => {
    it('should generate consistent key ID format', () => {
      const keyId = (handler as any).generateKeyId('HS256')

      expect(keyId).toMatch(/^hs256-[a-f0-9]{8}$/)
    })

    it('should generate different key IDs for different algorithms', () => {
      const hs256Id = (handler as any).generateKeyId('HS256')
      const rs256Id = (handler as any).generateKeyId('RS256')

      expect(hs256Id).toMatch(/^hs256-/)
      expect(rs256Id).toMatch(/^rs256-/)
    })
  })
})

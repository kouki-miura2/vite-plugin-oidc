/**
 * Tests for Token service
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { TokenService } from '../../../src/services/TokenService.js'
import type { JWTConfig, UserProfile } from '../../../src/types/index.js'

describe('TokenService', () => {
  let tokenService: TokenService
  const testConfig: JWTConfig = {
    algorithm: 'HS256',
    secret: 'test-secret-key',
  }
  const issuer = 'http://localhost:5173/oidc'

  beforeEach(() => {
    tokenService = new TokenService(testConfig, issuer, {}, '')
  })

  describe('Constructor', () => {
    it('should create instance with default expiration times', () => {
      const expiration = tokenService.getTokenExpiration()
      expect(expiration.accessToken).toBe(3600)
      expect(expiration.idToken).toBe(3600)
      expect(expiration.authorizationCode).toBe(600)
    })

    it('should use custom expiration times', () => {
      const customService = new TokenService(
        testConfig,
        issuer,
        {
          accessToken: 7200,
          idToken: 1800,
        },
        ''
      )
      const expiration = customService.getTokenExpiration()
      expect(expiration.accessToken).toBe(7200)
      expect(expiration.idToken).toBe(1800)
    })

    it('should return correct issuer and algorithm', () => {
      expect(tokenService.getIssuer()).toBe(issuer)
      expect(tokenService.getAlgorithm()).toBe('HS256')
    })
  })

  describe('Token Generation', () => {
    const userProfile: UserProfile = {
      sub: 'user123',
      name: 'Test User',
      email: 'test@example.com',
      email_verified: true,
    }

    it('should generate access token only when no openid scope', () => {
      const response = tokenService.generateTokens({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'profile email',
      })

      expect(response.access_token).toBeTruthy()
      expect(response.token_type).toBe('Bearer')
      expect(response.expires_in).toBe(3600)
      expect(response.scope).toBe('profile email')
      expect(response.id_token).toBeUndefined()
    })

    it('should generate both access and ID tokens with openid scope', () => {
      const response = tokenService.generateTokens({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'openid profile email',
        nonce: 'test-nonce',
        userProfile,
      })

      expect(response.access_token).toBeTruthy()
      expect(response.id_token).toBeTruthy()
      expect(response.token_type).toBe('Bearer')
      expect(response.expires_in).toBe(3600)
      expect(response.scope).toBe('openid profile email')
    })

    it('should generate standalone access token', () => {
      const token = tokenService.generateAccessToken({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'profile',
      })

      expect(token).toBeTruthy()
      expect(typeof token).toBe('string')
    })

    it('should generate standalone ID token', () => {
      const token = tokenService.generateIDToken({
        clientId: 'test_client',
        userId: 'user123',
        nonce: 'test-nonce',
        userProfile,
        scope: 'openid profile email',
      })

      expect(token).toBeTruthy()
      expect(typeof token).toBe('string')
    })
  })

  describe('Token Validation', () => {
    it('should validate access token', () => {
      const token = tokenService.generateAccessToken({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'profile',
      })

      const result = tokenService.validateAccessToken(token)
      expect(result.valid).toBe(true)
      expect(result.payload).toBeTruthy()
      expect(result.payload!.sub).toBe('user123')
    })

    it('should reject invalid access token', () => {
      const result = tokenService.validateAccessToken('invalid.token.here')
      expect(result.valid).toBe(false)
      expect(result.error).toBeTruthy()
    })

    it('should reject ID token as access token', () => {
      const idToken = tokenService.generateIDToken({
        clientId: 'test_client',
        userId: 'user123',
        nonce: 'test-nonce',
        userProfile: { sub: 'user123' },
      })

      const result = tokenService.validateAccessToken(idToken)
      expect(result.valid).toBe(false)
      expect(result.error).toContain('not an access token')
    })

    it('should validate ID token', () => {
      const token = tokenService.generateIDToken({
        clientId: 'test_client',
        userId: 'user123',
        nonce: 'test-nonce',
        userProfile: { sub: 'user123' },
      })

      const result = tokenService.validateIDToken(token, 'test_client')
      expect(result.valid).toBe(true)
      expect(result.payload).toBeTruthy()
    })

    it('should reject ID token with wrong audience', () => {
      const token = tokenService.generateIDToken({
        clientId: 'test_client',
        userId: 'user123',
        nonce: 'test-nonce',
        userProfile: { sub: 'user123' },
      })

      const result = tokenService.validateIDToken(token, 'wrong_client')
      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid token audience')
    })

    it('should reject token with wrong issuer', () => {
      const wrongService = new TokenService(
        testConfig,
        'http://wrong-issuer.com',
        {},
        ''
      )
      const token = wrongService.generateAccessToken({
        clientId: 'test_client',
        userId: 'user123',
      })

      const result = tokenService.validateAccessToken(token)
      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid token issuer')
    })
  })

  describe('ID Token Claims Building', () => {
    const userProfile: UserProfile = {
      sub: 'user123',
      name: 'Test User',
      given_name: 'Test',
      family_name: 'User',
      email: 'test@example.com',
      email_verified: true,
      picture: 'https://example.com/avatar.jpg',
      locale: 'en-US',
      custom_claim: 'custom_value',
    }

    it('should include profile claims with profile scope', () => {
      const response = tokenService.generateTokens({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'openid profile',
        userProfile,
      })

      // Decode the ID token to check claims
      const decoded = JSON.parse(
        Buffer.from(response.id_token!.split('.')[1], 'base64').toString()
      )

      expect(decoded.name).toBe('Test User')
      expect(decoded.given_name).toBe('Test')
      expect(decoded.family_name).toBe('User')
      expect(decoded.picture).toBe('https://example.com/avatar.jpg')
      expect(decoded.locale).toBe('en-US')
      expect(decoded.email).toBeUndefined() // Not included without email scope
    })

    it('should include email claims with email scope', () => {
      const response = tokenService.generateTokens({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'openid email',
        userProfile,
      })

      const decoded = JSON.parse(
        Buffer.from(response.id_token!.split('.')[1], 'base64').toString()
      )

      expect(decoded.email).toBe('test@example.com')
      expect(decoded.email_verified).toBe(true)
      expect(decoded.name).toBeUndefined() // Not included without profile scope
    })

    it('should include custom claims', () => {
      const response = tokenService.generateTokens({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'openid',
        userProfile,
      })

      const decoded = JSON.parse(
        Buffer.from(response.id_token!.split('.')[1], 'base64').toString()
      )

      expect(decoded.custom_claim).toBe('custom_value')
    })

    it('should handle empty user profile', () => {
      const response = tokenService.generateTokens({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'openid profile email',
      })

      expect(response.id_token).toBeTruthy()

      const decoded = JSON.parse(
        Buffer.from(response.id_token!.split('.')[1], 'base64').toString()
      )
      expect(decoded.sub).toBe('user123')
      expect(decoded.name).toBeUndefined()
      expect(decoded.email).toBeUndefined()
    })
  })
})

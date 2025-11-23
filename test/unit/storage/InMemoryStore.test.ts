/**
 * Tests for InMemoryStore class
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { InMemoryStore } from '../../../src/storage/InMemoryStore.js'
import type {
  AuthorizationCode,
  AccessToken,
  Session,
} from '../../../src/types/index.js'

describe('InMemoryStore', () => {
  let store: InMemoryStore

  beforeEach(() => {
    // Create store with short cleanup interval for testing
    store = new InMemoryStore(100)
  })

  afterEach(() => {
    store.stopCleanup()
  })

  describe('Authorization Codes', () => {
    it('should store and retrieve authorization codes', () => {
      const authCode: AuthorizationCode = {
        code: 'test_code_123',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge_123',
        codeChallengeMethod: 'S256',
        scope: 'openid profile',
        nonce: 'nonce_123',
        expiresAt: Date.now() + 600000, // 10 minutes from now
      }

      store.storeAuthorizationCode(authCode)
      const retrieved = store.getAuthorizationCode('test_code_123')

      expect(retrieved).toEqual(authCode)
    })

    it('should return null for non-existent authorization codes', () => {
      const retrieved = store.getAuthorizationCode('non_existent')
      expect(retrieved).toBeNull()
    })

    it('should return null for expired authorization codes', () => {
      const expiredAuthCode: AuthorizationCode = {
        code: 'expired_code',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge_123',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() - 1000, // 1 second ago (expired)
      }

      store.storeAuthorizationCode(expiredAuthCode)
      const retrieved = store.getAuthorizationCode('expired_code')

      expect(retrieved).toBeNull()
    })

    it('should delete authorization codes', () => {
      const authCode: AuthorizationCode = {
        code: 'delete_test',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge_123',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 600000,
      }

      store.storeAuthorizationCode(authCode)
      store.deleteAuthorizationCode('delete_test')
      const retrieved = store.getAuthorizationCode('delete_test')

      expect(retrieved).toBeNull()
    })
  })

  describe('Access Tokens', () => {
    it('should store and retrieve access tokens', () => {
      const accessToken: AccessToken = {
        token: 'access_token_123',
        userId: 'user_1',
        clientId: 'test_client',
        scope: 'openid profile',
        expiresAt: Date.now() + 3600000, // 1 hour from now
      }

      store.storeAccessToken(accessToken)
      const retrieved = store.getAccessToken('access_token_123')

      expect(retrieved).toEqual(accessToken)
    })

    it('should return null for non-existent access tokens', () => {
      const retrieved = store.getAccessToken('non_existent')
      expect(retrieved).toBeNull()
    })

    it('should return null for expired access tokens', () => {
      const expiredToken: AccessToken = {
        token: 'expired_token',
        userId: 'user_1',
        clientId: 'test_client',
        expiresAt: Date.now() - 1000, // 1 second ago (expired)
      }

      store.storeAccessToken(expiredToken)
      const retrieved = store.getAccessToken('expired_token')

      expect(retrieved).toBeNull()
    })

    it('should delete access tokens', () => {
      const accessToken: AccessToken = {
        token: 'delete_token',
        userId: 'user_1',
        clientId: 'test_client',
        expiresAt: Date.now() + 3600000,
      }

      store.storeAccessToken(accessToken)
      store.deleteAccessToken('delete_token')
      const retrieved = store.getAccessToken('delete_token')

      expect(retrieved).toBeNull()
    })
  })

  describe('Sessions', () => {
    it('should store and retrieve sessions', () => {
      const session: Session = {
        sessionId: 'session_123',
        userId: 'user_1',
        createdAt: Date.now(),
        expiresAt: Date.now() + 3600000, // 1 hour from now
      }

      store.storeSession(session)
      const retrieved = store.getSession('session_123')

      expect(retrieved).toEqual(session)
    })

    it('should return null for non-existent sessions', () => {
      const retrieved = store.getSession('non_existent')
      expect(retrieved).toBeNull()
    })

    it('should return null for expired sessions', () => {
      const expiredSession: Session = {
        sessionId: 'expired_session',
        userId: 'user_1',
        createdAt: Date.now() - 2000,
        expiresAt: Date.now() - 1000, // 1 second ago (expired)
      }

      store.storeSession(expiredSession)
      const retrieved = store.getSession('expired_session')

      expect(retrieved).toBeNull()
    })

    it('should delete sessions', () => {
      const session: Session = {
        sessionId: 'delete_session',
        userId: 'user_1',
        createdAt: Date.now(),
        expiresAt: Date.now() + 3600000,
      }

      store.storeSession(session)
      store.deleteSession('delete_session')
      const retrieved = store.getSession('delete_session')

      expect(retrieved).toBeNull()
    })
  })

  describe('Cleanup', () => {
    it('should clean up expired items manually', () => {
      // Add expired items
      const expiredAuthCode: AuthorizationCode = {
        code: 'expired_auth',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() - 1000,
      }

      const expiredToken: AccessToken = {
        token: 'expired_access',
        userId: 'user_1',
        clientId: 'test_client',
        expiresAt: Date.now() - 1000,
      }

      const expiredSession: Session = {
        sessionId: 'expired_sess',
        userId: 'user_1',
        createdAt: Date.now() - 2000,
        expiresAt: Date.now() - 1000,
      }

      // Add valid items
      const validAuthCode: AuthorizationCode = {
        code: 'valid_auth',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 600000,
      }

      store.storeAuthorizationCode(expiredAuthCode)
      store.storeAccessToken(expiredToken)
      store.storeSession(expiredSession)
      store.storeAuthorizationCode(validAuthCode)

      // Before cleanup
      let stats = store.getStats()
      expect(stats.authCodes).toBe(2)
      expect(stats.accessTokens).toBe(1)
      expect(stats.sessions).toBe(1)

      // Run cleanup
      store.cleanup()

      // After cleanup
      stats = store.getStats()
      expect(stats.authCodes).toBe(1)
      expect(stats.accessTokens).toBe(0)
      expect(stats.sessions).toBe(0)

      // Valid item should still be there
      expect(store.getAuthorizationCode('valid_auth')).not.toBeNull()
    })

    it('should automatically clean up expired items', async () => {
      // Create store with very short cleanup interval for testing
      const fastCleanupStore = new InMemoryStore(50) // 50ms cleanup interval

      try {
        // Add an item that will expire soon
        const shortLivedAuthCode: AuthorizationCode = {
          code: 'short_lived',
          clientId: 'test_client',
          userId: 'user_1',
          redirectUri: 'http://localhost:3000/callback',
          codeChallenge: 'challenge',
          codeChallengeMethod: 'S256',
          expiresAt: Date.now() + 25, // Expires in 25ms
        }

        fastCleanupStore.storeAuthorizationCode(shortLivedAuthCode)

        // Initially should be there
        expect(fastCleanupStore.getStats().authCodes).toBe(1)

        // Wait for expiration and automatic cleanup
        await new Promise((resolve) => setTimeout(resolve, 100))

        // Should be cleaned up automatically
        expect(fastCleanupStore.getStats().authCodes).toBe(0)
      } finally {
        fastCleanupStore.stopCleanup()
      }
    })

    it('should handle concurrent operations safely', () => {
      // Test concurrent storage and retrieval
      const authCodes: AuthorizationCode[] = []

      // Create multiple authorization codes
      for (let i = 0; i < 10; i++) {
        const authCode: AuthorizationCode = {
          code: `concurrent_code_${i}`,
          clientId: 'test_client',
          userId: `user_${i}`,
          redirectUri: 'http://localhost:3000/callback',
          codeChallenge: `challenge_${i}`,
          codeChallengeMethod: 'S256',
          expiresAt: Date.now() + 600000,
        }
        authCodes.push(authCode)
        store.storeAuthorizationCode(authCode)
      }

      // Verify all codes are stored
      expect(store.getStats().authCodes).toBe(10)

      // Retrieve all codes concurrently
      const retrievedCodes = authCodes.map((code) =>
        store.getAuthorizationCode(code.code),
      )

      // All should be retrieved successfully
      retrievedCodes.forEach((retrieved, index) => {
        expect(retrieved).toEqual(authCodes[index])
      })

      // Delete half of them
      for (let i = 0; i < 5; i++) {
        store.deleteAuthorizationCode(`concurrent_code_${i}`)
      }

      expect(store.getStats().authCodes).toBe(5)
    })

    it('should provide stats', () => {
      const stats = store.getStats()
      expect(stats).toHaveProperty('authCodes')
      expect(stats).toHaveProperty('accessTokens')
      expect(stats).toHaveProperty('sessions')
      expect(typeof stats.authCodes).toBe('number')
      expect(typeof stats.accessTokens).toBe('number')
      expect(typeof stats.sessions).toBe('number')
    })

    it('should clear all data', () => {
      // Add some data
      const authCode: AuthorizationCode = {
        code: 'test_code',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 600000,
      }

      store.storeAuthorizationCode(authCode)

      let stats = store.getStats()
      expect(stats.authCodes).toBe(1)

      // Clear all data
      store.clear()

      stats = store.getStats()
      expect(stats.authCodes).toBe(0)
      expect(stats.accessTokens).toBe(0)
      expect(stats.sessions).toBe(0)
    })
  })

  describe('Edge Cases', () => {
    it('should handle overwriting existing items', () => {
      const authCode1: AuthorizationCode = {
        code: 'same_code',
        clientId: 'client_1',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge_1',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 600000,
      }

      const authCode2: AuthorizationCode = {
        code: 'same_code', // Same code
        clientId: 'client_2', // Different client
        userId: 'user_2',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge_2',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 600000,
      }

      store.storeAuthorizationCode(authCode1)
      expect(store.getStats().authCodes).toBe(1)

      // Overwrite with same code
      store.storeAuthorizationCode(authCode2)
      expect(store.getStats().authCodes).toBe(1) // Still only 1 item

      // Should retrieve the latest one
      const retrieved = store.getAuthorizationCode('same_code')
      expect(retrieved?.clientId).toBe('client_2')
    })

    it('should handle items with minimal required fields', () => {
      // Authorization code with minimal fields
      const minimalAuthCode: AuthorizationCode = {
        code: 'minimal_code',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 600000,
        // No scope, nonce
      }

      store.storeAuthorizationCode(minimalAuthCode)
      const retrieved = store.getAuthorizationCode('minimal_code')
      expect(retrieved).toEqual(minimalAuthCode)

      // Access token with minimal fields
      const minimalToken: AccessToken = {
        token: 'minimal_token',
        userId: 'user_1',
        clientId: 'test_client',
        expiresAt: Date.now() + 3600000,
        // No scope
      }

      store.storeAccessToken(minimalToken)
      const retrievedToken = store.getAccessToken('minimal_token')
      expect(retrievedToken).toEqual(minimalToken)
    })

    it('should handle empty string keys gracefully', () => {
      // Test with empty string as code
      const authCode: AuthorizationCode = {
        code: '',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 600000,
      }

      store.storeAuthorizationCode(authCode)
      const retrieved = store.getAuthorizationCode('')
      expect(retrieved).toEqual(authCode)

      store.deleteAuthorizationCode('')
      expect(store.getAuthorizationCode('')).toBeNull()
    })

    it('should handle very large expiration times', () => {
      const farFutureAuthCode: AuthorizationCode = {
        code: 'far_future',
        clientId: 'test_client',
        userId: 'user_1',
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 365 * 24 * 60 * 60 * 1000, // 1 year from now
      }

      store.storeAuthorizationCode(farFutureAuthCode)
      const retrieved = store.getAuthorizationCode('far_future')
      expect(retrieved).toEqual(farFutureAuthCode)
    })

    it('should handle cleanup when no items exist', () => {
      // Ensure store is empty
      store.clear()
      expect(store.getStats().authCodes).toBe(0)

      // Cleanup should not throw error
      expect(() => store.cleanup()).not.toThrow()

      // Stats should still be zero
      expect(store.getStats().authCodes).toBe(0)
      expect(store.getStats().accessTokens).toBe(0)
      expect(store.getStats().sessions).toBe(0)
    })
  })
})

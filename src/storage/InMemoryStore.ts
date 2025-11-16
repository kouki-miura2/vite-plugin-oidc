/**
 * In-memory storage implementation for OIDC data
 * This is designed for development use only and does not persist data
 */

import type {
  InMemoryStore as IInMemoryStore,
  AuthorizationCode,
  AccessToken,
  Session,
} from '../types/index.js'

export class InMemoryStore implements IInMemoryStore {
  private authorizationCodes = new Map<string, AuthorizationCode>()
  private accessTokens = new Map<string, AccessToken>()
  private sessions = new Map<string, Session>()
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  constructor(cleanupIntervalMs: number = 60000) {
    // Default: 1 minute
    // Start automatic cleanup
    this.startCleanup(cleanupIntervalMs)
  }

  // Authorization codes management
  storeAuthorizationCode(code: AuthorizationCode): void {
    this.authorizationCodes.set(code.code, code)
  }

  getAuthorizationCode(code: string): AuthorizationCode | null {
    const authCode = this.authorizationCodes.get(code)
    if (!authCode) {
      return null
    }

    // Check if expired
    if (Date.now() > authCode.expiresAt) {
      this.authorizationCodes.delete(code)
      return null
    }

    return authCode
  }

  deleteAuthorizationCode(code: string): void {
    this.authorizationCodes.delete(code)
  }

  // Access tokens management
  storeAccessToken(token: AccessToken): void {
    this.accessTokens.set(token.token, token)
  }

  getAccessToken(token: string): AccessToken | null {
    const accessToken = this.accessTokens.get(token)
    if (!accessToken) {
      return null
    }

    // Check if expired
    if (Date.now() > accessToken.expiresAt) {
      this.accessTokens.delete(token)
      return null
    }

    return accessToken
  }

  deleteAccessToken(token: string): void {
    this.accessTokens.delete(token)
  }

  // Sessions management
  storeSession(session: Session): void {
    this.sessions.set(session.sessionId, session)
  }

  getSession(sessionId: string): Session | null {
    const session = this.sessions.get(sessionId)
    if (!session) {
      return null
    }

    // Check if expired
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(sessionId)
      return null
    }

    return session
  }

  deleteSession(sessionId: string): void {
    this.sessions.delete(sessionId)
  }

  // Cleanup expired items
  cleanup(): void {
    const now = Date.now()

    // Clean up expired authorization codes
    for (const [code, authCode] of this.authorizationCodes.entries()) {
      if (now > authCode.expiresAt) {
        this.authorizationCodes.delete(code)
      }
    }

    // Clean up expired access tokens
    for (const [token, accessToken] of this.accessTokens.entries()) {
      if (now > accessToken.expiresAt) {
        this.accessTokens.delete(token)
      }
    }

    // Clean up expired sessions
    for (const [sessionId, session] of this.sessions.entries()) {
      if (now > session.expiresAt) {
        this.sessions.delete(sessionId)
      }
    }
  }

  // Start automatic cleanup
  private startCleanup(intervalMs: number): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup()
    }, intervalMs)
  }

  // Stop automatic cleanup (useful for testing or shutdown)
  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
  }

  // Get statistics for debugging/monitoring
  getStats(): { authCodes: number; accessTokens: number; sessions: number } {
    return {
      authCodes: this.authorizationCodes.size,
      accessTokens: this.accessTokens.size,
      sessions: this.sessions.size,
    }
  }

  // Clear all data (useful for testing)
  clear(): void {
    this.authorizationCodes.clear()
    this.accessTokens.clear()
    this.sessions.clear()
  }
}

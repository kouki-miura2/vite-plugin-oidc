/**
 * JWT utility class for token generation and validation
 * Supports HS256 algorithm for development use
 */

import jwt from 'jsonwebtoken'
import type {
  JWTPayload,
  AccessTokenPayload,
  IDTokenPayload,
  TokenValidationResult,
  TokenGenerationOptions,
  JWTConfig,
} from '../types/index.js'

export class JWTUtil {
  private config: Required<JWTConfig>

  constructor(config: JWTConfig) {
    const algorithm = config.algorithm || 'HS256'

    // Validate configuration before setting defaults
    if (algorithm === 'HS256' && !config.secret) {
      throw new Error('JWT secret is required for HS256 algorithm')
    }

    if (algorithm === 'RS256' && (!config.privateKey || !config.publicKey)) {
      throw new Error(
        'Private and public keys are required for RS256 algorithm',
      )
    }

    // Set configuration with defaults
    this.config = {
      algorithm,
      secret: config.secret || 'dev-secret-key-change-in-production',
      privateKey: config.privateKey || '',
      publicKey: config.publicKey || '',
    }
  }

  /**
   * Generate a JWT token with the specified payload and options
   */
  generateToken(options: TokenGenerationOptions): string {
    const now = Math.floor(Date.now() / 1000)

    const payload: JWTPayload = {
      iss: options.issuer,
      aud: options.audience,
      sub: options.subject,
      iat: now,
      exp: now + options.expiresIn,
      ...options.additionalClaims,
    }

    const signOptions: jwt.SignOptions = {
      algorithm: this.config.algorithm,
    }

    const secret =
      this.config.algorithm === 'HS256'
        ? this.config.secret
        : this.config.privateKey

    return jwt.sign(payload, secret, signOptions)
  }

  /**
   * Generate an access token with standard claims
   */
  generateAccessToken(options: {
    issuer: string
    clientId: string
    userId: string
    expiresIn: number
    scope?: string
  }): string {
    return this.generateToken({
      issuer: options.issuer,
      audience: options.clientId,
      subject: options.userId,
      expiresIn: options.expiresIn,
      additionalClaims: {
        client_id: options.clientId,
        scope: options.scope || 'openid',
      },
    })
  }

  /**
   * Generate an ID token with OIDC standard claims
   */
  generateIDToken(options: {
    issuer: string
    clientId: string
    userId: string
    expiresIn: number
    nonce?: string
    userProfile?: {
      name?: string
      given_name?: string
      family_name?: string
      email?: string
      email_verified?: boolean
      picture?: string
      locale?: string
      [key: string]: unknown
    }
  }): string {
    const additionalClaims: Record<string, unknown> = {}

    // Add nonce if provided
    if (options.nonce) {
      additionalClaims.nonce = options.nonce
    }

    // Add user profile claims if provided
    if (options.userProfile) {
      Object.assign(additionalClaims, options.userProfile)
    }

    return this.generateToken({
      issuer: options.issuer,
      audience: options.clientId,
      subject: options.userId,
      expiresIn: options.expiresIn,
      additionalClaims,
    })
  }

  /**
   * Validate a JWT token and return the payload
   */
  validateToken(token: string): TokenValidationResult {
    try {
      const secret =
        this.config.algorithm === 'HS256'
          ? this.config.secret
          : this.config.publicKey

      const verifyOptions: jwt.VerifyOptions = {
        algorithms: [this.config.algorithm],
      }

      const payload = jwt.verify(token, secret, verifyOptions) as JWTPayload

      // Additional validation
      const now = Math.floor(Date.now() / 1000)

      if (payload.exp && payload.exp < now) {
        return {
          valid: false,
          error: 'Token has expired',
        }
      }

      if (payload.iat && payload.iat > now + 60) {
        // Allow 60 seconds clock skew
        return {
          valid: false,
          error: 'Token issued in the future',
        }
      }

      return {
        valid: true,
        payload,
      }
    } catch (error) {
      let errorMessage = 'Invalid token'

      if (error instanceof jwt.JsonWebTokenError) {
        errorMessage = error.message
      } else if (error instanceof jwt.TokenExpiredError) {
        errorMessage = 'Token has expired'
      } else if (error instanceof jwt.NotBeforeError) {
        errorMessage = 'Token not active yet'
      }

      return {
        valid: false,
        error: errorMessage,
      }
    }
  }

  /**
   * Decode a JWT token without verification (for debugging)
   */
  decodeToken(token: string): JWTPayload | null {
    try {
      return jwt.decode(token) as JWTPayload
    } catch {
      return null
    }
  }

  /**
   * Get the algorithm used for signing
   */
  getAlgorithm(): string {
    return this.config.algorithm
  }

  /**
   * Verify if the token is an access token (has client_id claim)
   */
  isAccessToken(payload: JWTPayload): payload is AccessTokenPayload {
    return 'client_id' in payload
  }

  /**
   * Verify if the token is an ID token (typically has name or email claims)
   */
  isIDToken(payload: JWTPayload): payload is IDTokenPayload {
    return 'nonce' in payload || 'name' in payload || 'email' in payload
  }
}

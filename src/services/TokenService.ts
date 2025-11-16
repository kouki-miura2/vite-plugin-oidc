/**
 * Token service for generating OIDC-compliant access tokens and ID tokens
 */

import { JWTUtil } from '../utils/JWTUtil.js'
import type {
  UserProfile,
  JWTConfig,
  TokenExpirationConfig,
} from '../types/index.js'

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  id_token?: string
  scope?: string
}

export interface TokenGenerationRequest {
  clientId: string
  userId: string
  scope?: string
  nonce?: string
  userProfile?: UserProfile
}

export class TokenService {
  private jwtUtil: JWTUtil
  private issuer: string
  private tokenExpiration: Required<TokenExpirationConfig>
  private basePath: string

  constructor(
    jwtConfig: JWTConfig,
    issuer: string,
    tokenExpiration: TokenExpirationConfig = {},
    basePath: string
  ) {
    this.jwtUtil = new JWTUtil(jwtConfig)
    this.issuer = issuer
    this.basePath = basePath

    // Set default token expiration times
    this.tokenExpiration = {
      authorizationCode: tokenExpiration.authorizationCode || 600, // 10 minutes
      accessToken: tokenExpiration.accessToken || 3600, // 1 hour
      idToken: tokenExpiration.idToken || 3600, // 1 hour
    }
  }

  /**
   * Generate access token and ID token for a successful authorization
   */
  generateTokens(request: TokenGenerationRequest): TokenResponse {
    const { clientId, userId, scope, nonce, userProfile } = request

    // Generate access token
    const accessToken = this.jwtUtil.generateAccessToken({
      issuer: this.issuer,
      clientId,
      userId,
      expiresIn: this.tokenExpiration.accessToken,
      scope,
    })

    // Prepare token response
    const tokenResponse: TokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.tokenExpiration.accessToken,
      scope,
    }

    // Generate ID token if openid scope is requested
    if (scope && scope.includes('openid')) {
      const idToken = this.jwtUtil.generateIDToken({
        issuer: this.issuer,
        clientId,
        userId,
        expiresIn: this.tokenExpiration.idToken,
        nonce,
        userProfile: this.buildIDTokenClaims(userProfile, scope),
      })

      tokenResponse.id_token = idToken
    }

    return tokenResponse
  }

  /**
   * Generate only an access token (for client credentials flow, etc.)
   */
  generateAccessToken(
    request: Omit<TokenGenerationRequest, 'nonce' | 'userProfile'>
  ): string {
    return this.jwtUtil.generateAccessToken({
      issuer: this.issuer,
      clientId: request.clientId,
      userId: request.userId,
      expiresIn: this.tokenExpiration.accessToken,
      scope: request.scope,
    })
  }

  /**
   * Generate only an ID token
   */
  generateIDToken(request: TokenGenerationRequest): string {
    const { clientId, userId, nonce, userProfile, scope } = request

    return this.jwtUtil.generateIDToken({
      issuer: this.issuer,
      clientId,
      userId,
      expiresIn: this.tokenExpiration.idToken,
      nonce,
      userProfile: this.buildIDTokenClaims(userProfile, scope),
    })
  }

  /**
   * Validate an access token
   */
  validateAccessToken(token: string): {
    valid: boolean
    payload?: any
    error?: string
  } {
    const result = this.jwtUtil.validateToken(token)

    if (!result.valid || !result.payload) {
      return result
    }

    // Verify it's an access token
    if (!this.jwtUtil.isAccessToken(result.payload)) {
      return {
        valid: false,
        error: 'Token is not an access token',
      }
    }

    // Verify issuer
    if (result.payload.iss !== this.issuer) {
      return {
        valid: false,
        error: 'Invalid token issuer',
      }
    }

    return result
  }

  /**
   * Validate an ID token
   */
  validateIDToken(
    token: string,
    expectedClientId?: string
  ): { valid: boolean; payload?: any; error?: string } {
    const result = this.jwtUtil.validateToken(token)

    if (!result.valid || !result.payload) {
      return result
    }

    // Verify issuer
    if (result.payload.iss !== this.issuer) {
      return {
        valid: false,
        error: 'Invalid token issuer',
      }
    }

    // Verify audience if provided
    if (expectedClientId && result.payload.aud !== expectedClientId) {
      return {
        valid: false,
        error: 'Invalid token audience',
      }
    }

    return result
  }

  /**
   * Build ID token claims based on requested scope
   */
  private buildIDTokenClaims(
    userProfile?: UserProfile,
    scope?: string
  ): Record<string, any> {
    if (!userProfile) {
      return {}
    }

    const claims: Record<string, any> = {}
    const scopes = scope ? scope.split(' ') : []
    const isKeycloakMode = this.basePath && this.basePath.includes('/realms')

    // Always include sub claim
    claims.sub = userProfile.sub

    // Include profile claims if profile scope is requested
    if (scopes.includes('profile')) {
      if (userProfile.name) claims.name = userProfile.name
      if (userProfile.given_name) claims.given_name = userProfile.given_name
      if (userProfile.family_name) claims.family_name = userProfile.family_name
      if (userProfile.picture) claims.picture = userProfile.picture
      if (userProfile.locale) claims.locale = userProfile.locale
    }

    // Include email claims if email scope is requested
    if (scopes.includes('email')) {
      if (userProfile.email) claims.email = userProfile.email
      if (userProfile.email_verified !== undefined)
        claims.email_verified = userProfile.email_verified
    }

    // Add Keycloak-specific claims when in Keycloak mode
    if (isKeycloakMode) {
      // preferred_username is commonly used by Keycloak
      if (userProfile.username) {
        claims.preferred_username = userProfile.username
      } else if (userProfile.email) {
        claims.preferred_username = userProfile.email
      }

      // Add given_name and family_name even if profile scope is not requested (Keycloak behavior)
      if (userProfile.given_name) claims.given_name = userProfile.given_name
      if (userProfile.family_name) claims.family_name = userProfile.family_name

      // Add other Keycloak-specific claims
      if (userProfile.name) claims.name = userProfile.name
      if (userProfile.email) claims.email = userProfile.email
      if (userProfile.email_verified !== undefined)
        claims.email_verified = userProfile.email_verified
    }

    // Include any additional custom claims
    Object.keys(userProfile).forEach((key) => {
      if (
        ![
          'sub',
          'name',
          'given_name',
          'family_name',
          'email',
          'email_verified',
          'picture',
          'locale',
          'username',
        ].includes(key)
      ) {
        claims[key] = userProfile[key]
      }
    })

    return claims
  }

  /**
   * Get token expiration configuration
   */
  getTokenExpiration(): Required<TokenExpirationConfig> {
    return { ...this.tokenExpiration }
  }

  /**
   * Get the issuer URL
   */
  getIssuer(): string {
    return this.issuer
  }

  /**
   * Get the JWT algorithm being used
   */
  getAlgorithm(): string {
    return this.jwtUtil.getAlgorithm()
  }
}

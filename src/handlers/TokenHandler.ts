/**
 * Token Handler for OIDC Token Endpoint
 * Handles /token requests and manages token exchange
 */

import type {
  TokenHandler as ITokenHandler,
  Request,
  Response,
} from '../types/handlers.js'
import type {
  TokenParams,
  TokenResponse,
  ValidationResult,
  OIDCError,
} from '../types/oidc.js'
import type { InMemoryStore, AccessToken } from '../types/storage.js'
import type {
  UserAccount,
  ClientConfig,
  OIDCPluginConfig,
} from '../types/config.js'
import { TokenService } from '../services/TokenService.js'
import { PKCEUtil } from '../utils/PKCEUtil.js'
import { ValidationUtil } from '../utils/ValidationUtil.js'
import { logger } from '../utils/Logger.js'

export class TokenHandler implements ITokenHandler {
  private store: InMemoryStore
  private config: OIDCPluginConfig
  private users: UserAccount[]
  private clients: ClientConfig[]
  private tokenService: TokenService

  constructor(
    store: InMemoryStore,
    config: OIDCPluginConfig,
    users: UserAccount[],
    clients: ClientConfig[],
    tokenService: TokenService,
  ) {
    this.store = store
    this.config = config
    this.users = users
    this.clients = clients
    this.tokenService = tokenService
  }

  async handleToken(req: Request, res: Response): Promise<void> {
    const requestId = this.generateRequestId()

    try {
      // Only accept POST requests
      if (req.method !== 'POST') {
        const error = ValidationUtil.createErrorResponse(
          'invalid_request',
          'Token endpoint only accepts POST requests',
        )
        logger.logTokenError(error, { requestId })
        this.sendErrorResponse(res, error)
        return
      }

      // Parse token request parameters from body
      const params = await this.parseTokenParams(req)

      // Log the token request
      logger.logTokenRequest({
        clientId: params.client_id,
        grantType: params.grant_type,
        authorizationCode: params.code,
        requestId,
      })

      // Validate the token request
      const validation = this.validateTokenRequest(params)

      if (!validation.isValid) {
        logger.logTokenError(validation.error!, {
          clientId: params.client_id,
          grantType: params.grant_type,
          requestId,
        })
        this.sendErrorResponse(res, validation.error!)
        return
      }

      // Exchange authorization code for tokens
      try {
        const tokenResponse = this.exchangeCodeForTokens(
          params.code,
          params.code_verifier,
        )

        // Get user info for logging
        const authCode = this.store.getAuthorizationCode(params.code)
        if (authCode) {
          logger.logTokenSuccess({
            clientId: params.client_id,
            userId: authCode.userId,
            scope: authCode.scope,
            requestId,
          })
        }

        // Send successful token response
        res.statusCode = 200
        res.setHeader('Content-Type', 'application/json')
        res.setHeader('Cache-Control', 'no-store')
        res.setHeader('Pragma', 'no-cache')
        res.end(JSON.stringify(tokenResponse))
        return
      } catch {
        const oidcError = ValidationUtil.createErrorResponse(
          'invalid_grant',
          'Invalid authorization code or code verifier',
        )
        logger.logTokenError(oidcError, {
          clientId: params.client_id,
          grantType: params.grant_type,
          requestId,
        })
        this.sendErrorResponse(res, oidcError)
        return
      }
    } catch (error) {
      const oidcError = ValidationUtil.createErrorResponse(
        'server_error',
        'Internal server error',
      )

      logger.error(
        'Token handler error',
        {
          endpoint: '/token',
          requestId,
          errorMessage:
            error instanceof Error ? error.message : 'Unknown error',
        },
        error instanceof Error ? error : undefined,
      )

      this.sendErrorResponse(res, oidcError)
    }
  }

  validateTokenRequest(params: TokenParams): ValidationResult {
    return ValidationUtil.validateTokenRequest(params, this.clients)
  }

  exchangeCodeForTokens(code: string, codeVerifier: string): TokenResponse {
    // Retrieve and validate authorization code
    const authCode = this.store.getAuthorizationCode(code)
    if (!authCode) {
      throw new Error('Invalid authorization code')
    }

    // Verify PKCE code challenge
    if (
      !PKCEUtil.verifyCodeChallenge(
        codeVerifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod,
      )
    ) {
      throw new Error('Invalid code verifier')
    }

    // Find the user
    const user = this.users.find((u) => u.id === authCode.userId)
    if (!user) {
      throw new Error('User not found')
    }

    // Generate tokens using TokenService
    const tokenResponse = this.tokenService.generateTokens({
      clientId: authCode.clientId,
      userId: authCode.userId,
      scope: authCode.scope,
      nonce: authCode.nonce,
      userProfile: user.profile,
    })

    // Store the access token for later validation
    const tokenExpiration = this.tokenService.getTokenExpiration()
    const accessTokenData: AccessToken = {
      token: tokenResponse.access_token,
      userId: authCode.userId,
      clientId: authCode.clientId,
      scope: authCode.scope,
      expiresAt: Date.now() + tokenExpiration.accessToken * 1000,
    }

    this.store.storeAccessToken(accessTokenData)

    // Delete the authorization code (one-time use)
    this.store.deleteAuthorizationCode(code)

    return tokenResponse
  }

  private async parseTokenParams(req: Request): Promise<TokenParams> {
    // Parse form-encoded body
    const body = await this.parseFormBody(req)

    return {
      grant_type: body.grant_type || '',
      code: body.code || '',
      redirect_uri: body.redirect_uri || '',
      client_id: body.client_id || '',
      code_verifier: body.code_verifier || '',
    }
  }

  private async parseFormBody(req: Request): Promise<Record<string, string>> {
    const body = req.body
    const params: Record<string, string> = {}

    if (typeof body === 'string') {
      // Parse URL-encoded form data
      const searchParams = new URLSearchParams(body)
      for (const [key, value] of searchParams.entries()) {
        params[key] = value
      }
    } else if (typeof body === 'object' && body !== null) {
      // Body is already parsed as an object
      Object.assign(params, body)
    }

    return params
  }

  private generateRequestId(): string {
    return `token_${Date.now()}_${Math.random().toString(36).substring(2)}`
  }

  private sendErrorResponse(res: Response, error: OIDCError): void {
    const statusCode = ValidationUtil.getErrorStatusCode(error.error)

    res.statusCode = statusCode
    res.setHeader('Content-Type', 'application/json')
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('Pragma', 'no-cache')
    res.end(JSON.stringify(error))
  }
}

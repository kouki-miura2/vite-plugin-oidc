/**
 * Handler interfaces for OIDC endpoints
 */

import {
  AuthorizationParams,
  TokenParams,
  TokenResponse,
  ValidationResult,
  TokenValidationResult,
  DiscoveryDocument,
  JWKSDocument,
} from './oidc.js'
import { UserProfile, UserAccount } from './config.js'

// Define minimal HTTP types to avoid external dependencies
export interface Request {
  url?: string
  method?: string
  headers: Record<string, string | string[] | undefined>
  body?: any
  query?: Record<string, string>
  readable?: boolean
  on?(event: 'data', listener: (chunk: Buffer) => void): void
  on?(event: 'end', listener: () => void): void
  on?(event: 'error', listener: (error: Error) => void): void
  on?(event: string, listener: (...args: any[]) => void): void
}

export interface Response {
  statusCode?: number
  setHeader(name: string, value: string): void
  end(data?: string): void
}

export interface AuthorizationHandler {
  handleAuthorize(req: Request, res: Response): Promise<void>
  validateAuthorizationRequest(params: AuthorizationParams): ValidationResult
  generateAuthorizationCode(
    clientId: string,
    userId: string,
    codeChallenge: string,
  ): string
}

export interface TokenHandler {
  handleToken(req: Request, res: Response): Promise<void>
  validateTokenRequest(params: TokenParams): ValidationResult
  exchangeCodeForTokens(code: string, codeVerifier: string): TokenResponse
}

export interface UserInfoHandler {
  handleUserInfo(req: Request, res: Response): Promise<void>
  validateAccessToken(token: string): TokenValidationResult
  getUserInfo(userId: string): UserProfile | null
}

export interface DiscoveryHandler {
  handleDiscovery(req: Request, res: Response): Promise<void>
  generateDiscoveryDocument(): DiscoveryDocument
}

export interface JWKSHandler {
  handleJWKS(req: Request, res: Response): Promise<void>
  generateJWKS(): JWKSDocument
}

export interface LoginUIHandler {
  handleLoginPage(req: Request, res: Response): Promise<void>
  handleLoginSubmit(req: Request, res: Response): Promise<void>
  generateLoginHTML(users: UserAccount[], error?: string): string
}

export interface LogoutHandler {
  handleLogout(req: Request, res: Response): Promise<void>
}

/**
 * Export all OIDC handlers
 */

export { DiscoveryHandler } from './DiscoveryHandler.js'
export { JWKSHandler } from './JWKSHandler.js'
export { AuthorizationHandler } from './AuthorizationHandler.js'
export { LoginUIHandler } from './LoginUIHandler.js'
export { TokenHandler } from './TokenHandler.js'
export { UserInfoHandler } from './UserInfoHandler.js'
export { LogoutHandler } from './LogoutHandler.js'
export { ThirdPartyCookiesHandler } from './ThirdPartyCookiesHandler.js'

// Re-export handler interfaces for convenience
export type {
  DiscoveryHandler as IDiscoveryHandler,
  JWKSHandler as IJWKSHandler,
  AuthorizationHandler as IAuthorizationHandler,
  LoginUIHandler as ILoginUIHandler,
  TokenHandler as ITokenHandler,
  LogoutHandler as ILogoutHandler,
  Request,
  Response,
} from '../types/handlers.js'

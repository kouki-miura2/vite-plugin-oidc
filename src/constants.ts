/**
 * Constants used throughout the OIDC plugin
 */

// OIDC endpoint paths
export const ENDPOINTS = {
  DISCOVERY: '/.well-known/openid-configuration',
  AUTHORIZE: '/authorize',
  TOKEN: '/token',
  USERINFO: '/userinfo',
  JWKS: '/jwks',
  LOGIN: '/login'
} as const;

// OIDC error codes
export const ERROR_CODES = {
  INVALID_REQUEST: 'invalid_request',
  INVALID_CLIENT: 'invalid_client',
  INVALID_GRANT: 'invalid_grant',
  UNAUTHORIZED_CLIENT: 'unauthorized_client',
  UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type',
  UNSUPPORTED_RESPONSE_TYPE: 'unsupported_response_type',
  INVALID_SCOPE: 'invalid_scope',
  ACCESS_DENIED: 'access_denied',
  SERVER_ERROR: 'server_error',
  INVALID_TOKEN: 'invalid_token',
  INSUFFICIENT_SCOPE: 'insufficient_scope'
} as const;

// Supported OIDC parameters
export const SUPPORTED = {
  RESPONSE_TYPES: ['code'],
  GRANT_TYPES: ['authorization_code'],
  CODE_CHALLENGE_METHODS: ['S256'],
  SCOPES: ['openid', 'profile', 'email'],
  CLAIMS: ['sub', 'name', 'email', 'email_verified'],
  TOKEN_ENDPOINT_AUTH_METHODS: ['none']
} as const;

// Default token expiration times (in seconds)
export const DEFAULT_EXPIRATION = {
  AUTHORIZATION_CODE: 600, // 10 minutes
  ACCESS_TOKEN: 3600, // 1 hour
  ID_TOKEN: 3600, // 1 hour
  SESSION: 86400 // 24 hours
} as const;
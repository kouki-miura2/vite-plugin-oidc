/**
 * Configuration interfaces for the OIDC plugin
 */

export interface UserProfile {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  locale?: string;
  [key: string]: any; // Additional custom claims
}

export interface UserAccount {
  id: string;
  username: string;
  password: string;
  profile: UserProfile;
}

export interface ClientConfig {
  client_id: string;
  redirect_uris: string[];
  response_types?: string[];
  grant_types?: string[];
}

export interface JWTConfig {
  algorithm?: 'HS256' | 'RS256';
  secret?: string;
  privateKey?: string;
  publicKey?: string;
}

export interface TokenExpirationConfig {
  authorizationCode?: number; // seconds, default: 600
  accessToken?: number; // seconds, default: 3600
  idToken?: number; // seconds, default: 3600
}

export interface DevelopmentConfig {
  enableLogging?: boolean;
  showWarnings?: boolean;
}

export interface LoginUIConfig {
  title?: string;
}

export interface OIDCPluginConfig {
  // Base path for OIDC endpoints (default: '/oidc')
  basePath?: string;
  
  // Issuer URL (default: http://localhost:{port}{basePath})
  issuer?: string;
  
  // JWT signing configuration
  jwt?: JWTConfig;
  
  // Multiple user accounts for testing
  users?: UserAccount[];
  
  // Client configuration
  clients?: ClientConfig[];
  
  // Token expiration settings
  tokenExpiration?: TokenExpirationConfig;
  
  // Development settings
  development?: DevelopmentConfig;
  
  // Login UI customization
  loginUI?: LoginUIConfig;
}
/**
 * OIDC protocol related types and interfaces
 */

export interface AuthorizationParams {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope?: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: string;
  nonce?: string;
  response_mode?: string;
}

export interface TokenParams {
  grant_type: string;
  code: string;
  redirect_uri: string;
  client_id: string;
  code_verifier: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  id_token?: string;
  scope?: string;
}

export interface OIDCError {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export interface ValidationResult {
  isValid: boolean;
  error?: OIDCError;
}

export interface TokenValidationResult {
  isValid: boolean;
  userId?: string;
  clientId?: string;
  scope?: string;
  error?: string;
}

export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  code_challenge_methods_supported: string[];
  scopes_supported: string[];
  claims_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  
  // Optional additional fields for better compatibility
  subject_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  response_modes_supported?: string[];
  end_session_endpoint?: string;
  claims_parameter_supported?: boolean;
  request_parameter_supported?: boolean;
  request_uri_parameter_supported?: boolean;
}

export interface JWKSDocument {
  keys: JWK[];
}

export interface JWK {
  kty: string;
  use?: string;
  key_ops?: string[];
  alg?: string;
  kid?: string;
  n?: string;
  e?: string;
  k?: string;
}
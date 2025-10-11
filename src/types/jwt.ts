/**
 * JWT-related type definitions
 */

export interface JWTPayload {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  exp: number;
  [key: string]: any;
}

export interface AccessTokenPayload extends JWTPayload {
  scope?: string;
  client_id: string;
}

export interface IDTokenPayload extends JWTPayload {
  nonce?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  locale?: string;
}

export interface TokenValidationResult {
  valid: boolean;
  payload?: JWTPayload;
  error?: string;
}

export interface TokenGenerationOptions {
  issuer: string;
  audience: string;
  subject: string;
  expiresIn: number;
  additionalClaims?: Record<string, any>;
}
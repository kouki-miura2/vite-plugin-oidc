/**
 * Storage-related type definitions
 */

export interface AuthorizationCode {
  code: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope?: string;
  nonce?: string;
  expiresAt: number;
}

export interface AccessToken {
  token: string;
  userId: string;
  clientId: string;
  scope?: string;
  expiresAt: number;
}

export interface Session {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
}

export interface InMemoryStore {
  // Authorization codes
  storeAuthorizationCode(code: AuthorizationCode): void;
  getAuthorizationCode(code: string): AuthorizationCode | null;
  deleteAuthorizationCode(code: string): void;
  
  // Access tokens
  storeAccessToken(token: AccessToken): void;
  getAccessToken(token: string): AccessToken | null;
  deleteAccessToken(token: string): void;
  
  // Sessions
  storeSession(session: Session): void;
  getSession(sessionId: string): Session | null;
  deleteSession(sessionId: string): void;
  
  // Cleanup expired items
  cleanup(): void;
}
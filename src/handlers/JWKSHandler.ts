/**
 * JWKS Handler for JSON Web Key Set endpoint
 * Implements /jwks endpoint for token verification
 */

import crypto from 'crypto';
import type { 
  JWKSHandler as IJWKSHandler,
  Request,
  Response 
} from '../types/handlers.js';
import type { JWKSDocument, JWK } from '../types/oidc.js';
import type { OIDCPluginConfig } from '../types/config.js';

export class JWKSHandler implements IJWKSHandler {
  private config: OIDCPluginConfig;
  private cachedJWKS: JWKSDocument | null = null;

  constructor(config: OIDCPluginConfig) {
    this.config = config;
  }

  /**
   * Handle JWKS requests
   */
  async handleJWKS(req: Request, res: Response): Promise<void> {
    try {
      const jwksDocument = this.generateJWKS();
      
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
      res.setHeader('Access-Control-Allow-Origin', '*'); // Allow CORS for JWKS
      res.statusCode = 200;
      res.end(JSON.stringify(jwksDocument, null, 2));
      
      if (this.config.development?.enableLogging) {
        console.log('[OIDC JWKS] JWKS document served');
      }
    } catch (error) {
      console.error('[OIDC JWKS] Error serving JWKS document:', error);
      
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 500;
      res.end(JSON.stringify({
        error: 'server_error',
        error_description: 'Internal server error while generating JWKS document'
      }));
    }
  }

  /**
   * Generate JWKS document with public key information
   */
  generateJWKS(): JWKSDocument {
    // Use cached JWKS if available (keys don't change during runtime)
    if (this.cachedJWKS) {
      return this.cachedJWKS;
    }

    const algorithm = this.config.jwt?.algorithm || 'HS256';
    const keys: JWK[] = [];

    if (algorithm === 'HS256') {
      // For HS256, we create a symmetric key JWK
      // Note: In production, symmetric keys should not be exposed in JWKS
      // This is for development/testing purposes only
      const secret = this.config.jwt?.secret || 'dev-secret-key-change-in-production';
      
      keys.push({
        kty: 'oct', // Octet sequence (symmetric key)
        use: 'sig', // Signature use
        alg: 'HS256',
        kid: this.generateKeyId('HS256'),
        k: this.base64UrlEncode(Buffer.from(secret, 'utf8'))
      });

      // Add warning for development use
      if (this.config.development?.showWarnings !== false) {
        console.warn('[OIDC JWKS] Warning: Exposing symmetric key in JWKS is for development only!');
      }
    } else if (algorithm === 'RS256') {
      // For RS256, extract public key components
      const publicKey = this.config.jwt?.publicKey;
      
      if (!publicKey) {
        throw new Error('Public key is required for RS256 algorithm');
      }

      const jwk = this.extractRSAPublicKeyComponents(publicKey);
      keys.push({
        kty: 'RSA',
        use: 'sig',
        alg: 'RS256',
        kid: this.generateKeyId('RS256'),
        ...jwk
      });
    }

    this.cachedJWKS = { keys };
    return this.cachedJWKS;
  }

  /**
   * Extract RSA public key components (n, e) from PEM format
   */
  private extractRSAPublicKeyComponents(publicKeyPem: string): { n: string; e: string } {
    try {
      // Create a crypto KeyObject from the PEM
      const keyObject = crypto.createPublicKey(publicKeyPem);
      
      // Export as JWK to get n and e components
      const jwk = keyObject.export({ format: 'jwk' }) as any;
      
      if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
        throw new Error('Invalid RSA public key format');
      }

      return {
        n: jwk.n,
        e: jwk.e
      };
    } catch (error) {
      throw new Error(`Failed to extract RSA public key components: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Generate a key ID for the JWK
   */
  private generateKeyId(algorithm: string): string {
    const timestamp = Date.now();
    const hash = crypto.createHash('sha256')
      .update(`${algorithm}-${timestamp}`)
      .digest('hex')
      .substring(0, 8);
    
    return `${algorithm.toLowerCase()}-${hash}`;
  }

  /**
   * Base64URL encode a buffer
   */
  private base64UrlEncode(buffer: Buffer): string {
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Clear cached JWKS (useful for testing or key rotation)
   */
  clearCache(): void {
    this.cachedJWKS = null;
  }

  /**
   * Get the current algorithm
   */
  getAlgorithm(): string {
    return this.config.jwt?.algorithm || 'HS256';
  }
}
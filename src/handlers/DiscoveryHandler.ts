/**
 * Discovery Handler for OIDC Discovery endpoint
 * Implements /.well-known/openid-configuration endpoint
 */

import type { 
  DiscoveryHandler as IDiscoveryHandler,
  Request,
  Response 
} from '../types/handlers.js';
import type { DiscoveryDocument } from '../types/oidc.js';
import type { OIDCPluginConfig } from '../types/config.js';
import { ENDPOINTS, SUPPORTED } from '../constants.js';

export class DiscoveryHandler implements IDiscoveryHandler {
  private config: OIDCPluginConfig;
  private issuer: string;
  private basePath: string;

  constructor(config: OIDCPluginConfig, issuer: string) {
    this.config = config;
    this.issuer = issuer;
    this.basePath = config.basePath || '/oidc';
  }

  /**
   * Handle OIDC Discovery requests
   */
  async handleDiscovery(req: Request, res: Response): Promise<void> {
    try {
      const discoveryDocument = this.generateDiscoveryDocument();
      
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
      res.statusCode = 200;
      res.end(JSON.stringify(discoveryDocument, null, 2));
      
      if (this.config.development?.enableLogging) {
        console.log('[OIDC Discovery] Discovery document served');
      }
    } catch (error) {
      console.error('[OIDC Discovery] Error serving discovery document:', error);
      
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 500;
      res.end(JSON.stringify({
        error: 'server_error',
        error_description: 'Internal server error while generating discovery document'
      }));
    }
  }

  /**
   * Generate OIDC Discovery document with all required endpoints
   */
  generateDiscoveryDocument(): DiscoveryDocument {
    const baseUrl = this.issuer.endsWith(this.basePath) 
      ? this.issuer 
      : `${this.issuer}${this.basePath}`;

    return {
      issuer: this.issuer,
      authorization_endpoint: `${baseUrl}${ENDPOINTS.AUTHORIZE}`,
      token_endpoint: `${baseUrl}${ENDPOINTS.TOKEN}`,
      userinfo_endpoint: `${baseUrl}${ENDPOINTS.USERINFO}`,
      jwks_uri: `${baseUrl}${ENDPOINTS.JWKS}`,
      response_types_supported: [...SUPPORTED.RESPONSE_TYPES],
      grant_types_supported: [...SUPPORTED.GRANT_TYPES],
      code_challenge_methods_supported: [...SUPPORTED.CODE_CHALLENGE_METHODS],
      scopes_supported: [...SUPPORTED.SCOPES],
      claims_supported: [...SUPPORTED.CLAIMS],
      token_endpoint_auth_methods_supported: [...SUPPORTED.TOKEN_ENDPOINT_AUTH_METHODS],
      
      // Additional optional fields for better compatibility
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: [this.getSigningAlgorithm()],
      response_modes_supported: ['query'],
      
      // Additional endpoints that might be useful
      end_session_endpoint: `${baseUrl}/logout`,
      
      // Claims parameter support
      claims_parameter_supported: false,
      request_parameter_supported: false,
      request_uri_parameter_supported: false
    };
  }

  /**
   * Get the signing algorithm from JWT configuration
   */
  private getSigningAlgorithm(): string {
    return this.config.jwt?.algorithm || 'HS256';
  }

  /**
   * Get the issuer URL
   */
  getIssuer(): string {
    return this.issuer;
  }

  /**
   * Get the base path
   */
  getBasePath(): string {
    return this.basePath;
  }
}
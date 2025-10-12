/**
 * Authorization Handler for OIDC Authorization Endpoint
 * Handles /authorize requests and manages the authorization flow
 */

import type { 
  AuthorizationHandler as IAuthorizationHandler,
  Request, 
  Response 
} from '../types/handlers.js';
import type { 
  AuthorizationParams, 
  ValidationResult, 
  OIDCError 
} from '../types/oidc.js';
import type { 
  InMemoryStore, 
  AuthorizationCode 
} from '../types/storage.js';
import type { 
  UserAccount, 
  ClientConfig, 
  OIDCPluginConfig 
} from '../types/config.js';
import { ValidationUtil } from '../utils/ValidationUtil.js';
import { logger } from '../utils/Logger.js';

export class AuthorizationHandler implements IAuthorizationHandler {
  private store: InMemoryStore;
  private config: OIDCPluginConfig;
  private users: UserAccount[];
  private clients: ClientConfig[];

  constructor(
    store: InMemoryStore, 
    config: OIDCPluginConfig, 
    users: UserAccount[], 
    clients: ClientConfig[]
  ) {
    this.store = store;
    this.config = config;
    this.users = users;
    this.clients = clients;
  }

  async handleAuthorize(req: Request, res: Response): Promise<void> {
    const requestId = this.generateRequestId();
    
    try {
      // Parse query parameters from URL
      const params = this.parseAuthorizationParams(req);
      
      // Log the authorization request
      logger.logAuthorizationRequest({
        clientId: params.client_id,
        redirectUri: params.redirect_uri,
        responseType: params.response_type,
        scope: params.scope,
        state: params.state,
        codeChallenge: params.code_challenge,
        requestId
      });
      
      // Validate the authorization request
      const validation = this.validateAuthorizationRequest(params);
      
      if (!validation.isValid) {
        logger.logAuthorizationError(validation.error!, {
          clientId: params.client_id,
          redirectUri: params.redirect_uri,
          requestId
        });
        this.sendErrorResponse(res, validation.error!, params.redirect_uri, params.state, params.response_mode);
        return;
      }

      // Check if this is a silent SSO check (from iframe)
      const isSilentCheck = this.isSilentSSOCheck(req, params);
      console.log('Authorization - Is silent SSO check:', isSilentCheck);

      // Check if user is already authenticated (has session)
      const sessionId = this.getSessionFromRequest(req);
      console.log('Authorization - Session ID from request:', sessionId);
      const session = sessionId ? this.store.getSession(sessionId) : null;
      console.log('Authorization - Session found:', session ? 'Yes' : 'No');
      if (session) {
        console.log('Authorization - Session details:', { userId: session.userId, expiresAt: session.expiresAt, now: Date.now() });
      }

      if (session) {
        // User is authenticated, generate authorization code and redirect
        const authCode = this.generateAuthorizationCode(
          params.client_id, 
          session.userId, 
          params.code_challenge
        );

        // Store the authorization code
        const codeExpiration = Date.now() + (this.config.tokenExpiration?.authorizationCode || 600) * 1000;
        const authorizationCode: AuthorizationCode = {
          code: authCode,
          clientId: params.client_id,
          userId: session.userId,
          redirectUri: params.redirect_uri,
          codeChallenge: params.code_challenge,
          codeChallengeMethod: params.code_challenge_method,
          scope: params.scope,
          nonce: params.nonce,
          expiresAt: codeExpiration
        };

        this.store.storeAuthorizationCode(authorizationCode);

        // Log successful authorization
        logger.logAuthorizationSuccess({
          clientId: params.client_id,
          userId: session.userId,
          authorizationCode: authCode,
          requestId
        });

        // Redirect back to client with authorization code
        this.redirectWithCode(res, params.redirect_uri, authCode, params.state, params.response_mode);
      } else {
        // User not authenticated
        if (isSilentCheck) {
          // For silent SSO checks, return an error instead of redirecting
          console.log('Authorization - Silent SSO check failed, returning error');
          const oidcError = ValidationUtil.createErrorResponse(
            'login_required',
            'User authentication is required'
          );
          this.sendErrorResponse(res, oidcError, params.redirect_uri, params.state, params.response_mode);
        } else {
          // For normal requests, redirect to login page
          console.log('Authorization - No valid session found, redirecting to login');
          logger.debug('User not authenticated, redirecting to login', {
            endpoint: '/authorize',
            clientId: params.client_id,
            requestId
          });
          this.redirectToLogin(res, req.url || '');
        }
      }

    } catch (error) {
      const oidcError = {
        error: 'server_error',
        error_description: 'Internal server error'
      };
      
      logger.error('Authorization handler error', {
        endpoint: '/authorize',
        requestId,
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      }, error instanceof Error ? error : undefined);
      
      this.sendErrorResponse(res, oidcError);
    }
  }

  validateAuthorizationRequest(params: AuthorizationParams): ValidationResult {
    return ValidationUtil.validateAuthorizationRequest(params, this.clients);
  }

  generateAuthorizationCode(clientId: string, userId: string, codeChallenge: string): string {
    // Generate a secure random authorization code
    const timestamp = Date.now().toString();
    const randomBytes = Math.random().toString(36).substring(2);
    const codeData = `${clientId}:${userId}:${codeChallenge}:${timestamp}:${randomBytes}`;
    
    // Create a base64-encoded code
    return Buffer.from(codeData).toString('base64url');
  }

  private parseAuthorizationParams(req: Request): AuthorizationParams {
    const url = new URL(req.url || '', 'http://localhost');
    const searchParams = url.searchParams;

    return {
      client_id: searchParams.get('client_id') || '',
      redirect_uri: searchParams.get('redirect_uri') || '',
      response_type: searchParams.get('response_type') || '',
      scope: searchParams.get('scope') || undefined,
      state: searchParams.get('state') || undefined,
      code_challenge: searchParams.get('code_challenge') || '',
      code_challenge_method: searchParams.get('code_challenge_method') || '',
      nonce: searchParams.get('nonce') || undefined,
      response_mode: searchParams.get('response_mode') || undefined
    };
  }

  private getSessionFromRequest(req: Request): string | null {
    // Extract session ID from cookie
    const cookieHeader = req.headers.cookie;
    console.log('Authorization - Cookie header:', cookieHeader);
    if (!cookieHeader) {
      return null;
    }

    const cookies = this.parseCookies(cookieHeader as string);
    console.log('Authorization - Parsed cookies:', cookies);
    return cookies['oidc_session'] || null;
  }

  private parseCookies(cookieHeader: string): Record<string, string> {
    const cookies: Record<string, string> = {};
    cookieHeader.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies[name] = decodeURIComponent(value);
      }
    });
    return cookies;
  }

  private isSilentSSOCheck(req: Request, params: AuthorizationParams): boolean {
    // Check for prompt=none parameter (standard OIDC silent authentication)
    const url = new URL(req.url || '', 'http://localhost');
    const prompt = url.searchParams.get('prompt');
    if (prompt === 'none') {
      return true;
    }

    // Check if request comes from iframe (silent-check-sso.html)
    const referer = req.headers.referer || req.headers.referrer;
    if (referer && referer.includes('silent-check-sso.html')) {
      return true;
    }

    // Check User-Agent for iframe indicators (some browsers)
    const userAgent = req.headers['user-agent'] || '';
    if (userAgent.includes('iframe') || userAgent.includes('silent')) {
      return true;
    }

    return false;
  }

  private redirectToLogin(res: Response, originalUrl: string): void {
    const basePath = this.config.basePath || '/oidc';
    const loginUrl = `${basePath}/login?return_to=${encodeURIComponent(originalUrl)}`;
    
    res.statusCode = 302;
    res.setHeader('Location', loginUrl);
    res.end();
  }

  private redirectWithCode(res: Response, redirectUri: string, code: string, state?: string, responseMode?: string): void {
    const url = new URL(redirectUri);
    
    if (responseMode === 'fragment') {
      // Use fragment for keycloak-js compatibility
      let fragment = `code=${encodeURIComponent(code)}`;
      if (state) {
        fragment += `&state=${encodeURIComponent(state)}`;
      }
      url.hash = fragment;
    } else {
      // Use query parameters (default)
      url.searchParams.set('code', code);
      if (state) {
        url.searchParams.set('state', state);
      }
    }

    res.statusCode = 302;
    res.setHeader('Location', url.toString());
    res.end();
  }

  private generateRequestId(): string {
    return `auth_${Date.now()}_${Math.random().toString(36).substring(2)}`;
  }

  private sendErrorResponse(res: Response, error: OIDCError, redirectUri?: string, state?: string, responseMode?: string): void {
    const statusCode = ValidationUtil.getErrorStatusCode(error.error);
    
    if (redirectUri) {
      // Redirect error to client
      const url = new URL(redirectUri);
      
      if (responseMode === 'fragment') {
        // Use fragment for keycloak-js compatibility
        let fragment = `error=${encodeURIComponent(error.error)}`;
        if (error.error_description) {
          fragment += `&error_description=${encodeURIComponent(error.error_description)}`;
        }
        if (error.error_uri) {
          fragment += `&error_uri=${encodeURIComponent(error.error_uri)}`;
        }
        if (state) {
          fragment += `&state=${encodeURIComponent(state)}`;
        }
        url.hash = fragment;
      } else {
        // Use query parameters (default)
        url.searchParams.set('error', error.error);
        if (error.error_description) {
          url.searchParams.set('error_description', error.error_description);
        }
        if (error.error_uri) {
          url.searchParams.set('error_uri', error.error_uri);
        }
        if (state) {
          url.searchParams.set('state', state);
        }
      }

      res.statusCode = 302;
      res.setHeader('Location', url.toString());
      res.end();
    } else {
      // Send error as JSON response
      res.statusCode = statusCode;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(JSON.stringify(error));
    }
  }
}
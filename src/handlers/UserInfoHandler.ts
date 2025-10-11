/**
 * UserInfo Handler for OIDC UserInfo Endpoint
 * Handles /userinfo requests and returns user profile information
 */

import type { 
  UserInfoHandler as IUserInfoHandler,
  Request, 
  Response 
} from '../types/handlers.js';
import type { 
  TokenValidationResult, 
  OIDCError 
} from '../types/oidc.js';
import type { 
  InMemoryStore 
} from '../types/storage.js';
import type { 
  UserAccount, 
  UserProfile,
  OIDCPluginConfig 
} from '../types/config.js';
import { TokenService } from '../services/TokenService.js';
import { ValidationUtil } from '../utils/ValidationUtil.js';
import { logger } from '../utils/Logger.js';

export class UserInfoHandler implements IUserInfoHandler {
  private store: InMemoryStore;
  private config: OIDCPluginConfig;
  private users: UserAccount[];
  private tokenService: TokenService;

  constructor(
    store: InMemoryStore, 
    config: OIDCPluginConfig, 
    users: UserAccount[],
    tokenService: TokenService
  ) {
    this.store = store;
    this.config = config;
    this.users = users;
    this.tokenService = tokenService;
  }

  async handleUserInfo(req: Request, res: Response): Promise<void> {
    const requestId = this.generateRequestId();
    
    try {
      // Only accept GET requests
      if (req.method !== 'GET') {
        const error = ValidationUtil.createErrorResponse(
          'invalid_request',
          'UserInfo endpoint only accepts GET requests'
        );
        logger.logUserInfoError(error, { requestId });
        this.sendErrorResponse(res, error, 405);
        return;
      }

      // Extract access token from Authorization header
      const authHeader = req.headers.authorization || req.headers.Authorization;
      if (!authHeader) {
        const error = ValidationUtil.createErrorResponse(
          'invalid_token',
          'Missing Authorization header'
        );
        logger.logUserInfoError(error, { requestId });
        this.sendErrorResponse(res, error, 401);
        return;
      }

      // Parse Bearer token
      const tokenMatch = (authHeader as string).match(/^Bearer\s+(.+)$/i);
      if (!tokenMatch) {
        const error = ValidationUtil.createErrorResponse(
          'invalid_token',
          'Invalid Authorization header format. Expected: Bearer <token>'
        );
        logger.logUserInfoError(error, { requestId });
        this.sendErrorResponse(res, error, 401);
        return;
      }

      const accessToken = tokenMatch[1];

      // Validate access token format
      if (!ValidationUtil.isValidAccessToken(accessToken)) {
        const error = ValidationUtil.createErrorResponse(
          'invalid_token',
          'Invalid access token format'
        );
        logger.logUserInfoError(error, { requestId });
        this.sendErrorResponse(res, error, 401);
        return;
      }

      // Validate the access token
      const validation = this.validateAccessToken(accessToken);
      
      // Log the userinfo request
      logger.logUserInfoRequest({
        userId: validation.userId,
        clientId: validation.clientId,
        scope: validation.scope,
        requestId
      });
      
      if (!validation.isValid) {
        const error = ValidationUtil.createErrorResponse(
          'invalid_token',
          validation.error || 'Invalid access token'
        );
        logger.logUserInfoError(error, {
          userId: validation.userId,
          clientId: validation.clientId,
          requestId
        });
        this.sendErrorResponse(res, error, 401);
        return;
      }

      // Get user information
      const userInfo = this.getUserInfo(validation.userId!);
      if (!userInfo) {
        const error = ValidationUtil.createErrorResponse(
          'invalid_token',
          'User not found'
        );
        logger.logUserInfoError(error, {
          userId: validation.userId,
          clientId: validation.clientId,
          requestId
        });
        this.sendErrorResponse(res, error, 401);
        return;
      }

      // Filter user info based on token scope
      const filteredUserInfo = this.filterUserInfoByScope(userInfo, validation.scope);

      // Log successful userinfo response
      logger.logUserInfoSuccess({
        userId: validation.userId!,
        clientId: validation.clientId,
        requestId
      });

      // Send successful response
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(JSON.stringify(filteredUserInfo));

    } catch (error) {
      const oidcError = ValidationUtil.createErrorResponse(
        'server_error',
        'Internal server error'
      );
      
      logger.error('UserInfo handler error', {
        endpoint: '/userinfo',
        requestId,
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      }, error instanceof Error ? error : undefined);
      
      this.sendErrorResponse(res, oidcError, 500);
    }
  }

  validateAccessToken(token: string): TokenValidationResult {
    try {
      // First check if token exists in our store
      const storedToken = this.store.getAccessToken(token);
      if (!storedToken) {
        return {
          isValid: false,
          error: 'Token not found in store'
        };
      }

      // Check if token is expired
      if (storedToken.expiresAt <= Date.now()) {
        // Clean up expired token
        this.store.deleteAccessToken(token);
        return {
          isValid: false,
          error: 'Token has expired'
        };
      }

      // Validate token signature and claims using TokenService
      const jwtValidation = this.tokenService.validateAccessToken(token);
      if (!jwtValidation.valid) {
        return {
          isValid: false,
          error: jwtValidation.error || 'Invalid token signature or claims'
        };
      }

      // Return successful validation with token details
      return {
        isValid: true,
        userId: storedToken.userId,
        clientId: storedToken.clientId,
        scope: storedToken.scope
      };

    } catch (error) {
      return {
        isValid: false,
        error: `Token validation error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  getUserInfo(userId: string): UserProfile | null {
    const user = this.users.find(u => u.id === userId);
    if (!user) {
      return null;
    }

    // Return a copy of the user profile to avoid mutations
    return { ...user.profile };
  }

  /**
   * Filter user info based on the scope of the access token
   */
  private filterUserInfoByScope(userInfo: UserProfile, scope?: string): UserProfile {
    if (!scope) {
      // If no scope, return minimal info (just sub)
      return { sub: userInfo.sub };
    }

    const scopes = scope.split(' ');
    const filteredInfo: UserProfile = { sub: userInfo.sub };

    // Include profile claims if profile scope is present
    if (scopes.includes('profile')) {
      if (userInfo.name) filteredInfo.name = userInfo.name;
      if (userInfo.given_name) filteredInfo.given_name = userInfo.given_name;
      if (userInfo.family_name) filteredInfo.family_name = userInfo.family_name;
      if (userInfo.picture) filteredInfo.picture = userInfo.picture;
      if (userInfo.locale) filteredInfo.locale = userInfo.locale;
    }

    // Include email claims if email scope is present
    if (scopes.includes('email')) {
      if (userInfo.email) filteredInfo.email = userInfo.email;
      if (userInfo.email_verified !== undefined) filteredInfo.email_verified = userInfo.email_verified;
    }

    // Include any additional custom claims (always included for now)
    Object.keys(userInfo).forEach(key => {
      if (!['sub', 'name', 'given_name', 'family_name', 'email', 'email_verified', 'picture', 'locale'].includes(key)) {
        filteredInfo[key] = userInfo[key];
      }
    });

    return filteredInfo;
  }

  private generateRequestId(): string {
    return `userinfo_${Date.now()}_${Math.random().toString(36).substring(2)}`;
  }

  private sendErrorResponse(res: Response, error: OIDCError, statusCode?: number): void {
    const finalStatusCode = statusCode || ValidationUtil.getErrorStatusCode(error.error);
    
    res.statusCode = finalStatusCode;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    
    // For 401 errors, include WWW-Authenticate header
    if (finalStatusCode === 401) {
      res.setHeader('WWW-Authenticate', 'Bearer');
    }
    
    res.end(JSON.stringify(error));
  }
}
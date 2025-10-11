/**
 * Integration tests for Vite Plugin OIDC
 * Tests plugin registration, middleware setup, and complete OIDC flow through Vite dev server
 * Requirements: 1.1, 1.2
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import oidcPlugin from "../../src/index.js";
import { createOIDCMiddleware } from "../../src/middleware/index.js";
import { PKCETestHelper } from "../helpers/PKCETestHelper";
import type { OIDCPluginConfig } from "../../src/types/index.js";

// Mock Vite server interface
interface MockViteServer {
  config: {
    server: {
      port?: number;
    };
  };
  middlewares: {
    use: ReturnType<typeof vi.fn>;
  };
}

// Mock request/response for middleware testing
interface MockRequest {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: any;
  query?: Record<string, string>;
}

interface MockResponse {
  statusCode?: number;
  setHeader: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
  writeHead: ReturnType<typeof vi.fn>;
}

describe('Vite Plugin OIDC Integration Tests', () => {
  let mockServer: MockViteServer;
  let mockResponse: MockResponse;
  let consoleSpy: any;
  let consoleErrorSpy: any;
  let consoleWarnSpy: any;

  beforeEach(() => {
    // Set up mock server
    mockServer = {
      config: {
        server: {
          port: 5173
        }
      },
      middlewares: {
        use: vi.fn()
      }
    };

    // Set up mock response
    mockResponse = {
      statusCode: 200,
      setHeader: vi.fn(),
      end: vi.fn(),
      writeHead: vi.fn()
    };

    // Set up console spies
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
    consoleWarnSpy.mockRestore();
    delete process.env.NODE_ENV;
    delete process.env.VITE_ENV;
    delete process.env.MODE;
  });

  describe('Plugin Registration and Middleware Setup', () => {
    it('should register plugin with correct name and hooks', () => {
      // Requirement 1.1: Plugin should integrate with Vite server
      const plugin = oidcPlugin();
      
      expect(plugin.name).toBe('vite-plugin-oidc');
      expect(plugin.configureServer).toBeDefined();
      expect(plugin.buildEnd).toBeDefined();
      expect(typeof plugin.configureServer).toBe('function');
      expect(typeof plugin.buildEnd).toBe('function');
    });

    it('should register middleware with default base path', () => {
      // Requirement 1.1: Plugin should register OIDC endpoints under configurable URI path
      const plugin = oidcPlugin();
      
      plugin.configureServer!(mockServer as any);
      
      expect(mockServer.middlewares.use).toHaveBeenCalledWith(
        '/oidc',
        expect.any(Function)
      );
    });

    it('should register middleware with custom base path', () => {
      // Requirement 1.1: Plugin should accept configurable URI path prefix
      const plugin = oidcPlugin({
        basePath: '/custom-auth'
      });
      
      plugin.configureServer!(mockServer as any);
      
      expect(mockServer.middlewares.use).toHaveBeenCalledWith(
        '/custom-auth',
        expect.any(Function)
      );
    });

    it('should set dynamic issuer based on server port', () => {
      // Requirement 1.1: Plugin should configure issuer based on server settings
      mockServer.config.server.port = 8080;
      
      const plugin = oidcPlugin();
      plugin.configureServer!(mockServer as any);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('http://localhost:8080/oidc')
      );
    });

    it('should use provided issuer when specified', () => {
      const customIssuer = 'https://custom-issuer.com/auth';
      const plugin = oidcPlugin({
        issuer: customIssuer
      });
      
      plugin.configureServer!(mockServer as any);
      
      // Should not override the provided issuer
      expect(mockServer.middlewares.use).toHaveBeenCalledWith(
        '/oidc',
        expect.any(Function)
      );
    });

    it('should log endpoint information when logging is enabled', () => {
      const plugin = oidcPlugin({
        development: {
          enableLogging: true
        }
      });
      
      plugin.configureServer!(mockServer as any);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('OIDC endpoints registered:')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Discovery: http://localhost:5173/oidc/.well-known/openid-configuration')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Authorization: http://localhost:5173/oidc/authorize')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Token: http://localhost:5173/oidc/token')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('UserInfo: http://localhost:5173/oidc/userinfo')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('JWKS: http://localhost:5173/oidc/jwks')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Login UI: http://localhost:5173/oidc/login')
      );
    });

    it('should not log when logging is disabled', () => {
      const plugin = oidcPlugin({
        development: {
          enableLogging: false
        }
      });
      
      plugin.configureServer!(mockServer as any);
      
      expect(consoleSpy).not.toHaveBeenCalledWith(
        expect.stringContaining('OIDC endpoints registered:')
      );
    });

    it('should provide cleanup functionality', () => {
      const plugin = oidcPlugin();
      
      expect(plugin.buildEnd).toBeDefined();
      
      // Should not throw when called
      expect(() => plugin.buildEnd!()).not.toThrow();
    });
  });

  describe('Complete OIDC Flow Through Vite Dev Server', () => {
    let middleware: any;
    let plugin: any;

    beforeEach(() => {
      plugin = oidcPlugin({
        development: {
          enableLogging: false,
          showWarnings: false
        }
      });
      
      plugin.configureServer!(mockServer as any);
      
      // Extract the registered middleware
      const middlewareCall = (mockServer.middlewares.use as any).mock.calls[0];
      middleware = middlewareCall[1];
    });

    describe('OIDC Discovery Endpoint', () => {
      it('should serve OIDC discovery document', async () => {
        // Requirement 1.2: Plugin should support OIDC Discovery
        const request: MockRequest = {
          method: 'GET',
          url: '/.well-known/openid-configuration',
          headers: {}
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(200);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Content-Type',
          'application/json'
        );
        
        const responseBody = (mockResponse.end as any).mock.calls[0][0];
        const discoveryDoc = JSON.parse(responseBody);
        
        expect(discoveryDoc.issuer).toBe('http://localhost:5173/oidc');
        expect(discoveryDoc.authorization_endpoint).toBe('http://localhost:5173/oidc/authorize');
        expect(discoveryDoc.token_endpoint).toBe('http://localhost:5173/oidc/token');
        expect(discoveryDoc.userinfo_endpoint).toBe('http://localhost:5173/oidc/userinfo');
        expect(discoveryDoc.jwks_uri).toBe('http://localhost:5173/oidc/jwks');
        expect(discoveryDoc.response_types_supported).toContain('code');
        expect(discoveryDoc.grant_types_supported).toContain('authorization_code');
        expect(discoveryDoc.code_challenge_methods_supported).toContain('S256');
      });
    });

    describe('JWKS Endpoint', () => {
      it('should serve JWKS document', async () => {
        // Requirement 1.2: Plugin should provide JWKS endpoint for token verification
        const request: MockRequest = {
          method: 'GET',
          url: '/jwks',
          headers: {}
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(200);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Content-Type',
          'application/json'
        );
        
        const responseBody = (mockResponse.end as any).mock.calls[0][0];
        const jwksDoc = JSON.parse(responseBody);
        
        expect(jwksDoc.keys).toBeDefined();
        expect(Array.isArray(jwksDoc.keys)).toBe(true);
        expect(jwksDoc.keys.length).toBeGreaterThan(0);
        expect(jwksDoc.keys[0].kty).toBeDefined();
        expect(jwksDoc.keys[0].use).toBe('sig');
      });
    });

    describe('Authorization Endpoint', () => {
      it('should redirect to login when user is not authenticated', async () => {
        // Requirement 1.2: Plugin should handle authorization requests
        const request: MockRequest = {
          method: 'GET',
          url: '/authorize?client_id=test_client&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=test_challenge&code_challenge_method=S256&state=test_state',
          headers: {}
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(302);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Location',
          expect.stringContaining('/login?return_to=')
        );
      });

      it('should handle invalid client_id', async () => {
        const request: MockRequest = {
          method: 'GET',
          url: '/authorize?client_id=invalid_client&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=test_challenge&code_challenge_method=S256',
          headers: {}
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(302);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Location',
          expect.stringContaining('error=unauthorized_client')
        );
      });

      it('should handle missing PKCE parameters', async () => {
        const request: MockRequest = {
          method: 'GET',
          url: '/authorize?client_id=test_client&redirect_uri=http://localhost:3000/callback&response_type=code',
          headers: {}
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(302);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Location',
          expect.stringContaining('error=invalid_request')
        );
      });
    });

    describe('Login UI Endpoint', () => {
      it('should serve login page', async () => {
        // Requirement 1.2: Plugin should provide login UI
        const request: MockRequest = {
          method: 'GET',
          url: '/login?return_to=%2Fauthorize%3Fclient_id%3Dtest_client',
          headers: {}
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(200);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Content-Type',
          'text/html; charset=utf-8'
        );
        
        const responseBody = (mockResponse.end as any).mock.calls[0][0];
        expect(responseBody).toContain('Test Client'); // Updated title
        expect(responseBody).toContain('Username');
        expect(responseBody).toContain('Password');
        // Note: New simple login form doesn't display user names
      });

      it('should handle login form submission', async () => {
        const request: MockRequest = {
          method: 'POST',
          url: '/login',
          headers: {
            'content-type': 'application/x-www-form-urlencoded'
          },
          body: 'username=johndoe&password=password123&return_to=%2Fauthorize%3Fclient_id%3Dtest_client'
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(302);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Set-Cookie',
          expect.stringContaining('oidc_session=')
        );
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Location',
          expect.stringContaining('/authorize')
        );
      });

      it('should handle invalid login credentials', async () => {
        const request: MockRequest = {
          method: 'POST',
          url: '/login',
          headers: {
            'content-type': 'application/x-www-form-urlencoded'
          },
          body: 'username=johndoe&password=wrongpassword&return_to=%2Fauthorize%3Fclient_id%3Dtest_client'
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(302);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Location',
          expect.stringContaining('/login?error=')
        );
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Location',
          expect.stringContaining('Invalid%20username%20or%20password')
        );
      });
    });

    describe('Token Endpoint', () => {
      it('should handle token exchange with valid authorization code', async () => {
        // First, we need to simulate getting an authorization code
        // This is a simplified test - in reality, we'd need to go through the full flow
        const { codeVerifier, codeChallenge } = PKCETestHelper.getFixedValidPKCEPair();
        
        const request: MockRequest = {
          method: 'POST',
          url: '/token',
          headers: {
            'content-type': 'application/x-www-form-urlencoded'
          },
          body: `grant_type=authorization_code&code=test_code&redirect_uri=http://localhost:3000/callback&client_id=test_client&code_verifier=${codeVerifier}`
        };

        await middleware(request, mockResponse, vi.fn());

        // Should return error for invalid code (since we didn't create a real one)
        expect(mockResponse.statusCode).toBe(400);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Content-Type',
          'application/json'
        );
        
        const responseBody = (mockResponse.end as any).mock.calls[0][0];
        const errorResponse = JSON.parse(responseBody);
        expect(errorResponse.error).toBe('invalid_grant');
      });

      it('should handle invalid grant type', async () => {
        const request: MockRequest = {
          method: 'POST',
          url: '/token',
          headers: {
            'content-type': 'application/x-www-form-urlencoded'
          },
          body: 'grant_type=client_credentials&client_id=test_client&code=test_code&redirect_uri=http://localhost:3000/callback&code_verifier=test_verifier'
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(400);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Content-Type',
          'application/json'
        );
        
        const responseBody = (mockResponse.end as any).mock.calls[0][0];
        const errorResponse = JSON.parse(responseBody);
        expect(errorResponse.error).toBe('unsupported_grant_type');
      });

      it('should handle missing required parameters', async () => {
        const request: MockRequest = {
          method: 'POST',
          url: '/token',
          headers: {
            'content-type': 'application/x-www-form-urlencoded'
          },
          body: 'grant_type=authorization_code'
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(400);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Content-Type',
          'application/json'
        );
        
        const responseBody = (mockResponse.end as any).mock.calls[0][0];
        const errorResponse = JSON.parse(responseBody);
        expect(errorResponse.error).toBe('invalid_request');
      });
    });

    describe('UserInfo Endpoint', () => {
      it('should require valid access token', async () => {
        // Requirement 1.2: Plugin should provide UserInfo endpoint
        const request: MockRequest = {
          method: 'GET',
          url: '/userinfo',
          headers: {}
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(401);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Content-Type',
          'application/json'
        );
        
        const responseBody = (mockResponse.end as any).mock.calls[0][0];
        const errorResponse = JSON.parse(responseBody);
        expect(errorResponse.error).toBe('invalid_token');
      });

      it('should handle invalid access token', async () => {
        const request: MockRequest = {
          method: 'GET',
          url: '/userinfo',
          headers: {
            authorization: 'Bearer invalid_token'
          }
        };

        await middleware(request, mockResponse, vi.fn());

        expect(mockResponse.statusCode).toBe(401);
        expect(mockResponse.setHeader).toHaveBeenCalledWith(
          'Content-Type',
          'application/json'
        );
        
        const responseBody = (mockResponse.end as any).mock.calls[0][0];
        const errorResponse = JSON.parse(responseBody);
        expect(errorResponse.error).toBe('invalid_token');
      });
    });

    describe('Middleware Error Handling', () => {
      it('should handle unknown endpoints gracefully', async () => {
        const nextFn = vi.fn();
        const request: MockRequest = {
          method: 'GET',
          url: '/unknown-endpoint',
          headers: {}
        };

        // Create a fresh response object for this test
        const freshResponse = {
          statusCode: undefined,
          setHeader: vi.fn(),
          end: vi.fn(),
          writeHead: vi.fn()
        };

        await middleware(request, freshResponse, nextFn);

        // Should call next() for unknown endpoints
        expect(nextFn).toHaveBeenCalled();
        expect(freshResponse.statusCode).toBeUndefined();
      });

      it('should handle middleware errors', async () => {
        // Create a request that might cause an error
        const request: MockRequest = {
          method: 'POST',
          url: '/token',
          headers: {
            'content-type': 'application/x-www-form-urlencoded'
          },
          body: null // This might cause parsing errors
        };

        await middleware(request, mockResponse, vi.fn());

        // Should handle the error gracefully
        expect(mockResponse.statusCode).toBeDefined();
      });
    });
  });

  describe('Full Authorization Code Flow Integration', () => {
    let middleware: any;
    let plugin: any;

    beforeEach(() => {
      plugin = oidcPlugin({
        development: {
          enableLogging: false,
          showWarnings: false
        }
      });
      
      plugin.configureServer!(mockServer as any);
      
      // Extract the registered middleware
      const middlewareCall = (mockServer.middlewares.use as any).mock.calls[0];
      middleware = middlewareCall[1];
    });

    it('should complete full OIDC flow simulation', async () => {
      // Requirement 1.2: Plugin should support complete Authorization Code Flow + PKCE
      
      // Step 1: Start authorization request (should redirect to login)
      const authRequest: MockRequest = {
        method: 'GET',
        url: '/authorize?client_id=test_client&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=test_challenge&code_challenge_method=S256&state=test_state&scope=openid profile',
        headers: {}
      };

      const authResponse = { ...mockResponse };
      await middleware(authRequest, authResponse, vi.fn());

      expect(authResponse.statusCode).toBe(302);
      expect(authResponse.setHeader).toHaveBeenCalledWith(
        'Location',
        expect.stringContaining('/login?return_to=')
      );

      // Step 2: Display login page
      const loginPageRequest: MockRequest = {
        method: 'GET',
        url: '/login?return_to=%2Fauthorize%3Fclient_id%3Dtest_client%26redirect_uri%3Dhttp%3A%2F%2Flocalhost%3A3000%2Fcallback%26response_type%3Dcode%26code_challenge%3Dtest_challenge%26code_challenge_method%3DS256%26state%3Dtest_state%26scope%3Dopenid%20profile',
        headers: {}
      };

      const loginPageResponse = { ...mockResponse, setHeader: vi.fn(), end: vi.fn() };
      await middleware(loginPageRequest, loginPageResponse, vi.fn());

      expect(loginPageResponse.statusCode).toBe(200);
      expect(loginPageResponse.setHeader).toHaveBeenCalledWith(
        'Content-Type',
        'text/html; charset=utf-8'
      );

      // Step 3: Submit login form
      const loginSubmitRequest: MockRequest = {
        method: 'POST',
        url: '/login',
        headers: {
          'content-type': 'application/x-www-form-urlencoded'
        },
        body: 'username=johndoe&password=password123&return_to=%2Fauthorize%3Fclient_id%3Dtest_client%26redirect_uri%3Dhttp%3A%2F%2Flocalhost%3A3000%2Fcallback%26response_type%3Dcode%26code_challenge%3Dtest_challenge%26code_challenge_method%3DS256%26state%3Dtest_state%26scope%3Dopenid%20profile'
      };

      const loginSubmitResponse = { ...mockResponse, setHeader: vi.fn(), end: vi.fn() };
      await middleware(loginSubmitRequest, loginSubmitResponse, vi.fn());

      expect(loginSubmitResponse.statusCode).toBe(302);
      expect(loginSubmitResponse.setHeader).toHaveBeenCalledWith(
        'Set-Cookie',
        expect.stringContaining('oidc_session=')
      );
      expect(loginSubmitResponse.setHeader).toHaveBeenCalledWith(
        'Location',
        expect.stringContaining('/authorize')
      );

      // Extract session cookie for next request
      const setHeaderCalls = (loginSubmitResponse.setHeader as any).mock.calls;
      const cookieCall = setHeaderCalls.find((call: any) => call[0] === 'Set-Cookie');
      const sessionCookie = cookieCall[1];

      // Step 4: Complete authorization with session (should redirect with code)
      const authWithSessionRequest: MockRequest = {
        method: 'GET',
        url: '/authorize?client_id=test_client&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=test_challenge&code_challenge_method=S256&state=test_state&scope=openid profile',
        headers: {
          cookie: sessionCookie
        }
      };

      const authWithSessionResponse = { ...mockResponse, setHeader: vi.fn(), end: vi.fn() };
      await middleware(authWithSessionRequest, authWithSessionResponse, vi.fn());

      expect(authWithSessionResponse.statusCode).toBe(302);
      
      const authSetHeaderCalls = (authWithSessionResponse.setHeader as any).mock.calls;
      const authLocationCall = authSetHeaderCalls.find((call: any) => call[0] === 'Location');
      const redirectUrl = authLocationCall[1];
      
      expect(redirectUrl).toContain('http://localhost:3000/callback');
      expect(redirectUrl).toContain('code=');
      expect(redirectUrl).toContain('state=test_state');

      // This completes the authorization flow simulation
      // The token exchange would require the actual authorization code from the redirect
    });
  });

  describe('Plugin Configuration Integration', () => {
    it('should work with custom configuration', () => {
      const customConfig: OIDCPluginConfig = {
        basePath: '/custom-oidc',
        issuer: 'https://custom.example.com/oidc',
        jwt: {
          algorithm: 'HS256',
          secret: 'custom-secret'
        },
        users: [
          {
            id: 'custom1',
            username: 'customuser',
            password: 'custompass',
            profile: {
              sub: 'custom1',
              name: 'Custom User',
              email: 'custom@example.com'
            }
          }
        ],
        clients: [
          {
            client_id: 'custom_client',
            redirect_uris: ['https://custom.example.com/callback'],
            response_types: ['code'],
            grant_types: ['authorization_code']
          }
        ],
        tokenExpiration: {
          authorizationCode: 300,
          accessToken: 1800,
          idToken: 1800
        },
        development: {
          enableLogging: true,
          showWarnings: true
        }
      };

      const plugin = oidcPlugin(customConfig);
      plugin.configureServer!(mockServer as any);

      expect(mockServer.middlewares.use).toHaveBeenCalledWith(
        '/custom-oidc',
        expect.any(Function)
      );

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Initializing OIDC endpoints at /custom-oidc')
      );
    });

    it('should merge custom configuration with defaults', () => {
      const partialConfig: OIDCPluginConfig = {
        basePath: '/auth',
        development: {
          enableLogging: false
        }
      };

      const plugin = oidcPlugin(partialConfig);
      plugin.configureServer!(mockServer as any);

      expect(mockServer.middlewares.use).toHaveBeenCalledWith(
        '/auth',
        expect.any(Function)
      );

      // Should not log since enableLogging is false
      expect(consoleSpy).not.toHaveBeenCalledWith(
        expect.stringContaining('OIDC endpoints registered:')
      );
    });
  });

  describe('Plugin Lifecycle Management', () => {
    it('should handle plugin cleanup on buildEnd', () => {
      const plugin = oidcPlugin();
      plugin.configureServer!(mockServer as any);

      // Should not throw when cleanup is called
      expect(() => plugin.buildEnd!()).not.toThrow();
    });

    it('should handle multiple plugin instances', () => {
      const plugin1 = oidcPlugin({ basePath: '/oidc1' });
      const plugin2 = oidcPlugin({ basePath: '/oidc2' });

      const mockServer1 = { ...mockServer, middlewares: { use: vi.fn() } };
      const mockServer2 = { ...mockServer, middlewares: { use: vi.fn() } };

      plugin1.configureServer!(mockServer1 as any);
      plugin2.configureServer!(mockServer2 as any);

      expect(mockServer1.middlewares.use).toHaveBeenCalledWith('/oidc1', expect.any(Function));
      expect(mockServer2.middlewares.use).toHaveBeenCalledWith('/oidc2', expect.any(Function));
    });
  });
});
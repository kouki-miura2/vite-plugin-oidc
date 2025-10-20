/**
 * Unit tests for ThirdPartyCookiesHandler
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ThirdPartyCookiesHandler } from '../../../src/handlers/ThirdPartyCookiesHandler.js';
import type { OIDCPluginConfig } from '../../../src/types/config.js';
import type { Request, Response } from '../../../src/types/handlers.js';

describe('ThirdPartyCookiesHandler', () => {
  let handler: ThirdPartyCookiesHandler;
  let mockConfig: OIDCPluginConfig;
  let mockRequest: Request;
  let mockResponse: Response;

  beforeEach(() => {
    mockConfig = {
      basePath: '/oidc',
      jwt: {
        algorithm: 'HS256',
        secret: 'test-secret'
      },
      development: {
        enableLogging: false,
        showWarnings: false
      }
    };

    handler = new ThirdPartyCookiesHandler(mockConfig);

    mockRequest = {
      url: '/protocol/openid-connect/3p-cookies/step1.html',
      method: 'GET',
      headers: {
        host: 'localhost:5173'
      },
      query: {}
    };

    mockResponse = {
      statusCode: 200,
      setHeader: vi.fn(),
      end: vi.fn()
    };
  });

  describe('handleStep1', () => {
    it('should serve step1.html successfully', async () => {
      await handler.handleStep1(mockRequest, mockResponse);

      expect(mockResponse.statusCode).toBe(200);
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Content-Type', 'text/html; charset=utf-8');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store, no-cache, must-revalidate');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Pragma', 'no-cache');
      expect(mockResponse.end).toHaveBeenCalled();

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('<!doctype html>');
      expect(html).toContain('checkStorageAccess');
    });

    it('should generate correct step2 URL with basePath', async () => {
      await handler.handleStep1(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('http://localhost:5173/oidc/protocol/openid-connect/3p-cookies/step2.html');
    });

    it('should handle custom basePath', async () => {
      const customConfig = {
        ...mockConfig,
        basePath: '/auth'
      };
      const customHandler = new ThirdPartyCookiesHandler(customConfig);

      await customHandler.handleStep1(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('http://localhost:5173/auth/protocol/openid-connect/3p-cookies/step2.html');
    });

    it('should handle root basePath', async () => {
      const rootConfig = {
        ...mockConfig,
        basePath: '/'
      };
      const rootHandler = new ThirdPartyCookiesHandler(rootConfig);

      await rootHandler.handleStep1(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('http://localhost:5173/protocol/openid-connect/3p-cookies/step2.html');
    });

    it('should set secure cookie attributes for HTTPS', async () => {
      const httpsRequest = {
        ...mockRequest,
        headers: {
          ...mockRequest.headers,
          'x-forwarded-proto': 'https'
        }
      };

      await handler.handleStep1(httpsRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('Max-Age=60; SameSite=None; Secure');
    });

    it('should set non-secure cookie attributes for HTTP', async () => {
      await handler.handleStep1(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('Max-Age=60');
      expect(html).not.toContain('SameSite=None; Secure');
    });

    it('should detect HTTPS from x-forwarded-proto header', async () => {
      const forwardedRequest = {
        ...mockRequest,
        headers: {
          ...mockRequest.headers,
          'x-forwarded-proto': 'https'
        }
      };

      await handler.handleStep1(forwardedRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('https://localhost:5173');
    });

    it('should use HTTP for localhost by default', async () => {
      await handler.handleStep1(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('http://localhost:5173');
    });

    it('should log when logging is enabled', async () => {
      const loggingConfig = {
        ...mockConfig,
        development: {
          enableLogging: true,
          showWarnings: false
        }
      };
      const loggingHandler = new ThirdPartyCookiesHandler(loggingConfig);
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      await loggingHandler.handleStep1(mockRequest, mockResponse);

      expect(consoleSpy).toHaveBeenCalledWith('[3P Cookies] Step1 served', expect.any(Object));

      consoleSpy.mockRestore();
    });

    it('should handle errors gracefully', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      // Mock setHeader to throw an error only on first call (before the catch block)
      let callCount = 0;
      const originalSetHeader = mockResponse.setHeader;
      mockResponse.setHeader = vi.fn().mockImplementation((key, value) => {
        callCount++;
        if (callCount === 1) {
          throw new Error('Test error');
        }
        // Allow subsequent calls in the catch block
        return originalSetHeader;
      });

      await handler.handleStep1(mockRequest, mockResponse);

      expect(consoleSpy).toHaveBeenCalledWith('[3P Cookies] Error serving step1.html:', expect.any(Error));
      expect(mockResponse.statusCode).toBe(500);

      consoleSpy.mockRestore();
    });
  });

  describe('handleStep2', () => {
    it('should serve step2.html successfully', async () => {
      await handler.handleStep2(mockRequest, mockResponse);

      expect(mockResponse.statusCode).toBe(200);
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Content-Type', 'text/html; charset=utf-8');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store, no-cache, must-revalidate');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Pragma', 'no-cache');
      expect(mockResponse.end).toHaveBeenCalled();

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('<!doctype html>');
      expect(html).toContain('KEYCLOAK_3P_COOKIE');
    });

    it('should check for test cookies in step2', async () => {
      await handler.handleStep2(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('document.cookie.includes("KEYCLOAK_3P_COOKIE")');
    });

    it('should send postMessage to parent window', async () => {
      await handler.handleStep2(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('window.parent.postMessage');
      expect(html).toContain('supported');
      expect(html).toContain('unsupported');
    });

    it('should log when logging is enabled', async () => {
      const loggingConfig = {
        ...mockConfig,
        development: {
          enableLogging: true,
          showWarnings: false
        }
      };
      const loggingHandler = new ThirdPartyCookiesHandler(loggingConfig);
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      await loggingHandler.handleStep2(mockRequest, mockResponse);

      expect(consoleSpy).toHaveBeenCalledWith('[3P Cookies] Step2 served');

      consoleSpy.mockRestore();
    });

    it('should handle errors gracefully', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      let callCount = 0;
      const originalSetHeader = mockResponse.setHeader;
      mockResponse.setHeader = vi.fn().mockImplementation((key, value) => {
        callCount++;
        if (callCount === 1) {
          throw new Error('Test error');
        }
        return originalSetHeader;
      });

      await handler.handleStep2(mockRequest, mockResponse);

      expect(consoleSpy).toHaveBeenCalledWith('[3P Cookies] Error serving step2.html:', expect.any(Error));
      expect(mockResponse.statusCode).toBe(500);

      consoleSpy.mockRestore();
    });
  });

  describe('handleLoginStatusIframe', () => {
    it('should serve login-status-iframe.html successfully', async () => {
      await handler.handleLoginStatusIframe(mockRequest, mockResponse);

      expect(mockResponse.statusCode).toBe(200);
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Content-Type', 'text/html; charset=utf-8');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store, no-cache, must-revalidate');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Pragma', 'no-cache');
      expect(mockResponse.end).toHaveBeenCalled();

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('<!doctype html>');
      expect(html).toContain('window.addEventListener');
    });

    it('should handle message events for session checking', async () => {
      await handler.handleLoginStatusIframe(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain("window.addEventListener('message'");
      expect(html).toContain('sessionState');
      expect(html).toContain('unchanged');
    });

    it('should notify parent when ready', async () => {
      await handler.handleLoginStatusIframe(mockRequest, mockResponse);

      const html = (mockResponse.end as any).mock.calls[0][0] as string;
      expect(html).toContain('window.parent !== window');
      expect(html).toContain("postMessage('ready'");
    });

    it('should log when logging is enabled', async () => {
      const loggingConfig = {
        ...mockConfig,
        development: {
          enableLogging: true,
          showWarnings: false
        }
      };
      const loggingHandler = new ThirdPartyCookiesHandler(loggingConfig);
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      await loggingHandler.handleLoginStatusIframe(mockRequest, mockResponse);

      expect(consoleSpy).toHaveBeenCalledWith('[Login Status Iframe] Served');

      consoleSpy.mockRestore();
    });

    it('should handle errors gracefully', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      let callCount = 0;
      const originalSetHeader = mockResponse.setHeader;
      mockResponse.setHeader = vi.fn().mockImplementation((key, value) => {
        callCount++;
        if (callCount === 1) {
          throw new Error('Test error');
        }
        return originalSetHeader;
      });

      await handler.handleLoginStatusIframe(mockRequest, mockResponse);

      expect(consoleSpy).toHaveBeenCalledWith('[Login Status Iframe] Error serving login-status-iframe.html:', expect.any(Error));
      expect(mockResponse.statusCode).toBe(500);

      consoleSpy.mockRestore();
    });
  });

  describe('basePath handling', () => {
    it('should use default basePath when not specified', () => {
      const configWithoutBasePath = {
        jwt: {
          algorithm: 'HS256' as const,
          secret: 'test-secret'
        }
      };
      const defaultHandler = new ThirdPartyCookiesHandler(configWithoutBasePath);

      expect((defaultHandler as any).basePath).toBe('/oidc');
    });

    it('should use custom basePath from config', () => {
      const customConfig = {
        ...mockConfig,
        basePath: '/custom-auth'
      };
      const customHandler = new ThirdPartyCookiesHandler(customConfig);

      expect((customHandler as any).basePath).toBe('/custom-auth');
    });
  });
});

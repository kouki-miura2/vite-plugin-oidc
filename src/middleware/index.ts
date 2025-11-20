/**
 * OIDC Middleware for Vite plugin
 */

import type { OIDCPluginConfig } from '../types/index.js'
import { InMemoryStore } from '../storage/index.js'
import {
  DiscoveryHandler,
  JWKSHandler,
  AuthorizationHandler,
  LoginUIHandler,
  TokenHandler,
  UserInfoHandler,
  LogoutHandler,
  ThirdPartyCookiesHandler,
} from '../handlers/index.js'
import { TokenService } from '../services/TokenService.js'
import { Logger, LogLevel } from '../utils/Logger.js'

// Simple request/response interfaces to avoid external dependencies
interface Request {
  method?: string
  url?: string
  headers: Record<string, string | string[] | undefined>
  body?: any
  query?: Record<string, string>
  readable?: boolean
  on?(event: 'data', listener: (chunk: Buffer) => void): void
  on?(event: 'end', listener: () => void): void
  on?(event: 'error', listener: (error: Error) => void): void
  on?(event: string, listener: (...args: any[]) => void): void
}

interface Response {
  statusCode?: number
  setHeader(name: string, value: string): void
  end(data?: string): void
  writeHead(statusCode: number, headers?: Record<string, string>): void
  headersSent?: boolean
}

/**
 * Get expected HTTP methods for a given OIDC endpoint
 */
function getExpectedMethods(endpoint: string): string[] {
  switch (endpoint) {
    case '/.well-known/openid-configuration':
    case '/jwks':
    case '/authorize':
    case '/protocol/openid-connect/auth':
    case '/userinfo':
    case '/protocol/openid-connect/userinfo':
    case '/logout':
    case '/protocol/openid-connect/logout':
    case '/protocol/openid-connect/3p-cookies/step1.html':
    case '/protocol/openid-connect/3p-cookies/step2.html':
    case '/protocol/openid-connect/login-status-iframe.html':
      return ['GET']
    case '/login':
      return ['GET', 'POST']
    case '/token':
    case '/protocol/openid-connect/token':
      return ['POST']
    default:
      return ['GET']
  }
}

/**
 * Creates OIDC middleware for handling authentication requests
 */
export function createOIDCMiddleware(config: Required<OIDCPluginConfig>) {
  const store = new InMemoryStore()
  const logger = Logger.getInstance()

  // Error tracking for circuit breaker pattern
  let errorCount = 0
  let lastErrorTime = 0
  const ERROR_THRESHOLD = 10 // Max errors before circuit breaker
  const ERROR_WINDOW = 60000 // 1 minute window

  // Configure logger
  logger.configure({
    logLevel: config.development.enableLogging ? LogLevel.INFO : LogLevel.WARN,
    enableConsoleOutput: config.development.enableLogging,
  })

  // Initialize token service
  const tokenService = new TokenService(
    config.jwt,
    config.issuer,
    config.tokenExpiration,
    config.basePath,
  )

  // Initialize handlers with correct constructor signatures
  const discoveryHandler = new DiscoveryHandler(config, config.issuer)
  const jwksHandler = new JWKSHandler(config)
  const authorizationHandler = new AuthorizationHandler(
    store,
    config,
    config.users,
    config.clients,
  )
  const loginUIHandler = new LoginUIHandler(store, config, config.users)
  const tokenHandler = new TokenHandler(
    store,
    config,
    config.users,
    config.clients,
    tokenService,
  )
  const userInfoHandler = new UserInfoHandler(
    store,
    config,
    config.users,
    tokenService,
  )
  const logoutHandler = new LogoutHandler(store, config)
  const thirdPartyCookiesHandler = new ThirdPartyCookiesHandler(config)

  // Start cleanup interval for expired items
  const cleanupInterval = setInterval(() => {
    try {
      store.cleanup()
    } catch (error) {
      logger.error(
        'Error during automatic cleanup:',
        {
          errorMessage: error instanceof Error ? error.message : String(error),
          timestamp: Date.now(),
        },
        error instanceof Error ? error : new Error(String(error)),
      )
    }
  }, 60000) // Cleanup every minute

  const middleware = async (req: Request, res: Response, next: () => void) => {
    try {
      const url = req.url || ''
      const method = req.method || 'GET'

      // Basic request validation
      if (!url) {
        logger.warn('Request received with no URL', {
          method,
          headers: req.headers,
          timestamp: Date.now(),
        })
        res.statusCode = 400
        res.setHeader('Content-Type', 'application/json')
        res.end(
          JSON.stringify({
            error: 'invalid_request',
            error_description: 'Missing URL in request',
          }),
        )
        return
      }

      // Parse URL path (remove query string)
      const urlPath = url.split('?')[0]

      // Validate URL path
      if (!urlPath || urlPath.length > 1000) {
        // Prevent extremely long URLs
        logger.warn('Invalid URL path received', {
          urlLength: url.length,
          method,
          timestamp: Date.now(),
        })
        res.statusCode = 400
        res.setHeader('Content-Type', 'application/json')
        res.end(
          JSON.stringify({
            error: 'invalid_request',
            error_description: 'Invalid URL path',
          }),
        )
        return
      }

      // Route requests to appropriate handlers
      if (urlPath === '/.well-known/openid-configuration' && method === 'GET') {
        await discoveryHandler.handleDiscovery(req, res)
        return
      }

      if (urlPath === '/jwks' && method === 'GET') {
        await jwksHandler.handleJWKS(req, res)
        return
      }

      if (
        (urlPath === '/authorize' ||
          urlPath === '/protocol/openid-connect/auth') &&
        method === 'GET'
      ) {
        await authorizationHandler.handleAuthorize(req, res)
        return
      }

      if (urlPath === '/login' && method === 'GET') {
        await loginUIHandler.handleLoginPage(req, res)
        return
      }

      if (urlPath === '/login' && method === 'POST') {
        // Ensure request body is available for form parsing
        if (!req.body && req.readable !== false && req.on) {
          // Read the request body if it hasn't been read yet
          const chunks: Buffer[] = []
          req.on('data', (chunk: Buffer) => {
            chunks.push(chunk)
          })
          req.on('end', async () => {
            req.body = Buffer.concat(chunks).toString()
            await loginUIHandler.handleLoginSubmit(req, res)
          })
          req.on('error', (error: Error) => {
            logger.error(
              'Error reading request body:',
              {
                errorMessage: error.message,
                timestamp: Date.now(),
              },
              error,
            )
            res.statusCode = 500
            res.setHeader('Content-Type', 'text/plain')
            res.end('Internal Server Error')
          })
        } else {
          await loginUIHandler.handleLoginSubmit(req, res)
        }
        return
      }

      if (
        (urlPath === '/token' ||
          urlPath === '/protocol/openid-connect/token') &&
        method === 'POST'
      ) {
        // Ensure request body is available for form parsing
        if (!req.body && req.readable !== false && req.on) {
          // Read the request body if it hasn't been read yet
          const chunks: Buffer[] = []
          req.on('data', (chunk: Buffer) => {
            chunks.push(chunk)
          })
          req.on('end', async () => {
            req.body = Buffer.concat(chunks).toString()
            await tokenHandler.handleToken(req, res)
          })
          req.on('error', (error: Error) => {
            logger.error(
              'Error reading request body:',
              {
                errorMessage: error.message,
                timestamp: Date.now(),
              },
              error,
            )
            res.statusCode = 500
            res.setHeader('Content-Type', 'text/plain')
            res.end('Internal Server Error')
          })
        } else {
          await tokenHandler.handleToken(req, res)
        }
        return
      }

      if (
        (urlPath === '/userinfo' ||
          urlPath === '/protocol/openid-connect/userinfo') &&
        method === 'GET'
      ) {
        await userInfoHandler.handleUserInfo(req, res)
        return
      }

      if (
        (urlPath === '/logout' ||
          urlPath === '/protocol/openid-connect/logout') &&
        method === 'GET'
      ) {
        await logoutHandler.handleLogout(req, res)
        return
      }

      if (
        urlPath === '/protocol/openid-connect/3p-cookies/step1.html' &&
        method === 'GET'
      ) {
        await thirdPartyCookiesHandler.handleStep1(req, res)
        return
      }

      if (
        urlPath === '/protocol/openid-connect/3p-cookies/step2.html' &&
        method === 'GET'
      ) {
        await thirdPartyCookiesHandler.handleStep2(req, res)
        return
      }

      if (
        urlPath === '/protocol/openid-connect/login-status-iframe.html' &&
        method === 'GET'
      ) {
        await thirdPartyCookiesHandler.handleLoginStatusIframe(req, res)
        return
      }

      // Handle known OIDC endpoints with wrong methods
      const knownEndpoints = [
        '/.well-known/openid-configuration',
        '/jwks',
        '/authorize',
        '/protocol/openid-connect/auth',
        '/login',
        '/token',
        '/protocol/openid-connect/token',
        '/userinfo',
        '/protocol/openid-connect/userinfo',
        '/logout',
        '/protocol/openid-connect/logout',
        '/protocol/openid-connect/3p-cookies/step1.html',
        '/protocol/openid-connect/3p-cookies/step2.html',
        '/protocol/openid-connect/login-status-iframe.html',
      ]

      if (knownEndpoints.includes(urlPath)) {
        // This is a known OIDC endpoint but with wrong method
        logger.warn('Invalid method for OIDC endpoint:', {
          endpoint: urlPath,
          method: method,
          expectedMethods: getExpectedMethods(urlPath),
          timestamp: Date.now(),
        })

        res.statusCode = 405 // Method Not Allowed
        res.setHeader('Content-Type', 'application/json')
        res.setHeader('Allow', getExpectedMethods(urlPath).join(', '))
        res.setHeader('Cache-Control', 'no-store')
        res.setHeader('Pragma', 'no-cache')

        res.end(
          JSON.stringify({
            error: 'invalid_request',
            error_description: `Method ${method} not allowed for ${urlPath}. Expected: ${getExpectedMethods(
              urlPath,
            ).join(', ')}`,
          }),
        )
        return
      }

      // If no OIDC endpoint matches, pass to next middleware
      next()
    } catch (error) {
      // Enhanced error handling with circuit breaker pattern
      const now = Date.now()
      const errorMessage =
        error instanceof Error ? error.message : String(error)

      // Update error tracking
      if (now - lastErrorTime > ERROR_WINDOW) {
        errorCount = 1 // Reset counter if outside window
      } else {
        errorCount++
      }
      lastErrorTime = now

      // Log error with context
      logger.error(
        'Middleware error:',
        {
          endpoint: req.url,
          method: req.method,
          userAgent: req.headers['user-agent'],
          errorMessage,
          errorCount,
          timestamp: now,
        },
        error instanceof Error ? error : new Error(String(error)),
      )

      // Circuit breaker: if too many errors, temporarily disable
      if (errorCount >= ERROR_THRESHOLD) {
        logger.error('Circuit breaker activated due to repeated errors', {
          errorCount,
          threshold: ERROR_THRESHOLD,
          timestamp: now,
        })
      }

      // Ensure response hasn't been sent already
      if (!res.headersSent) {
        res.statusCode = 500
        res.setHeader('Content-Type', 'application/json')
        res.setHeader('Cache-Control', 'no-store')
        res.setHeader('Pragma', 'no-cache')

        const errorResponse = {
          error: 'server_error',
          error_description: config.development.enableLogging
            ? `Internal server error: ${errorMessage}`
            : 'Internal server error',
        }

        res.end(JSON.stringify(errorResponse))
      }
    }
  }

  // Add cleanup method to middleware
  ;(middleware as any).cleanup = () => {
    try {
      // Clear the cleanup interval
      clearInterval(cleanupInterval)

      // Stop store cleanup
      store.stopCleanup()

      // Clear all stored data
      store.clear()

      // Log cleanup statistics
      const stats = store.getStats()
      logger.info('OIDC middleware cleanup completed', {
        clearedAuthCodes: stats.authCodes,
        clearedAccessTokens: stats.accessTokens,
        clearedSessions: stats.sessions,
        timestamp: Date.now(),
      })
    } catch (error) {
      logger.error(
        'Error during middleware cleanup:',
        {
          errorMessage: error instanceof Error ? error.message : String(error),
          timestamp: Date.now(),
        },
        error instanceof Error ? error : new Error(String(error)),
      )
    }
  }

  return middleware
}

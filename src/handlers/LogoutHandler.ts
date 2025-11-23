/**
 * Logout Handler for OIDC End Session Endpoint
 * Handles logout requests and session termination
 */

import type { Request, Response } from '../types/handlers.js'
import type { InMemoryStore } from '../types/storage.js'
import type { OIDCPluginConfig } from '../types/config.js'
import { Logger } from '../utils/Logger.js'

export class LogoutHandler {
  private store: InMemoryStore
  private config: OIDCPluginConfig
  private logger: Logger

  constructor(store: InMemoryStore, config: OIDCPluginConfig) {
    this.store = store
    this.config = config
    this.logger = Logger.getInstance()
  }

  async handleLogout(req: Request, res: Response): Promise<void> {
    const requestId = `logout_${Date.now()}_${Math.random()
      .toString(36)
      .substring(2)}`

    try {
      this.logger.info('Logout request received', {
        endpoint: '/logout',
        requestId,
        timestamp: Date.now(),
      })

      // Parse query parameters
      const url = new URL(req.url || '', 'http://localhost')
      const postLogoutRedirectUri = url.searchParams.get(
        'post_logout_redirect_uri',
      )
      const state = url.searchParams.get('state')

      // Get session from cookie
      const sessionId = this.getSessionFromCookie(req)

      if (sessionId) {
        // Remove session from store
        this.store.deleteSession(sessionId)

        this.logger.info('Session terminated', {
          endpoint: '/logout',
          sessionId: '[REDACTED]',
          requestId,
          timestamp: Date.now(),
        })
      }

      // Clear session cookie
      const cookieValue = `oidc_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`
      res.setHeader('Set-Cookie', cookieValue)

      // Handle redirect
      if (postLogoutRedirectUri) {
        // Validate redirect URI (basic validation)
        if (this.isValidPostLogoutRedirectUri(postLogoutRedirectUri)) {
          let redirectUrl = postLogoutRedirectUri

          // Add state parameter if provided
          if (state) {
            const separator = redirectUrl.includes('?') ? '&' : '?'
            redirectUrl += `${separator}state=${encodeURIComponent(state)}`
          }

          this.logger.info('Logout redirect', {
            endpoint: '/logout',
            redirectUri: postLogoutRedirectUri,
            requestId,
            timestamp: Date.now(),
          })

          res.statusCode = 302
          res.setHeader('Location', redirectUrl)
          res.end()
          return
        } else {
          this.logger.warn('Invalid post_logout_redirect_uri', {
            endpoint: '/logout',
            redirectUri: postLogoutRedirectUri,
            requestId,
            timestamp: Date.now(),
          })
        }
      }

      // Show simple logout confirmation message
      res.statusCode = 200
      res.setHeader('Content-Type', 'text/plain; charset=utf-8')
      res.end('Logout successful')

      this.logger.info('Logout successful', {
        endpoint: '/logout',
        requestId,
        timestamp: Date.now(),
      })
    } catch (error) {
      this.logger.error(
        'Logout handler error',
        {
          endpoint: '/logout',
          requestId,
          errorMessage: error instanceof Error ? error.message : String(error),
          timestamp: Date.now(),
        },
        error instanceof Error ? error : new Error(String(error)),
      )

      res.statusCode = 500
      res.setHeader('Content-Type', 'text/plain')
      res.end('Internal Server Error')
    }
  }

  private getSessionFromCookie(req: Request): string | null {
    const cookieHeader = req.headers.cookie
    if (!cookieHeader) return null

    const cookies = cookieHeader.toString().split(';')
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=')
      if (name === 'oidc_session') {
        return value
      }
    }
    return null
  }

  private isValidPostLogoutRedirectUri(uri: string): boolean {
    try {
      const url = new URL(uri)

      // Basic validation - only allow http/https
      if (!['http:', 'https:'].includes(url.protocol)) {
        return false
      }

      // For development, allow localhost
      if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
        return true
      }

      // In production, you would validate against registered redirect URIs
      // For now, allow any HTTPS URL
      return url.protocol === 'https:'
    } catch {
      return false
    }
  }
}

/**
 * Third Party Cookies Handler for Keycloak-js compatibility
 * Implements /protocol/openid-connect/3p-cookies/step1.html and step2.html endpoints
 */

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import type { Request, Response } from '../types/handlers.js'
import type { OIDCPluginConfig } from '../types/config.js'

// Get current directory for ES modules
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Load HTML templates at build time
const step1HTML = fs.readFileSync(
  path.join(__dirname, '../assets/templates/3p-cookies-step1.html'),
  'utf-8',
)

const step2HTML = fs.readFileSync(
  path.join(__dirname, '../assets/templates/3p-cookies-step2.html'),
  'utf-8',
)

const loginStatusIframeHTML = fs.readFileSync(
  path.join(__dirname, '../assets/templates/login-status-iframe.html'),
  'utf-8',
)

export class ThirdPartyCookiesHandler {
  private config: OIDCPluginConfig
  private basePath: string

  constructor(config: OIDCPluginConfig) {
    this.config = config
    this.basePath = config.basePath || '/oidc'
  }

  /**
   * Handle step1.html - Initial 3rd party cookie detection
   * This page checks for Storage Access API support and sets test cookies
   */
  async handleStep1(req: Request, res: Response): Promise<void> {
    try {
      // Determine if we're in a secure context
      const protocol =
        req.headers['x-forwarded-proto'] ||
        (req.headers['host']?.includes('localhost') ? 'http' : 'https')
      const isSecure = protocol === 'https'

      // Build absolute URL for step2
      const host = req.headers['host'] || 'localhost:5173'
      // Ensure proper path construction with basePath
      const basePathNormalized = this.basePath === '/' ? '' : this.basePath
      const step2Url = `${protocol}://${host}${basePathNormalized}/protocol/openid-connect/3p-cookies/step2.html`

      // Generate cookie attributes based on environment
      const sameSiteCookieAttrs = isSecure
        ? 'Max-Age=60; SameSite=None; Secure'
        : 'Max-Age=60'

      const regularCookieAttrs = 'Max-Age=60'

      // Replace template placeholders
      const html = step1HTML
        .replace('{{step2Url}}', step2Url)
        .replace('{{sameSiteCookieAttrs}}', sameSiteCookieAttrs)
        .replace('{{regularCookieAttrs}}', regularCookieAttrs)

      res.statusCode = 200
      res.setHeader('Content-Type', 'text/html; charset=utf-8')
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
      res.setHeader('Pragma', 'no-cache')
      res.end(html)

      if (this.config.development?.enableLogging) {
        console.log('[3P Cookies] Step1 served', {
          isSecure,
          step2Url,
        })
      }
    } catch (error) {
      console.error('[3P Cookies] Error serving step1.html:', error)

      res.statusCode = 500
      res.setHeader('Content-Type', 'text/plain')
      res.end('Internal Server Error')
    }
  }

  /**
   * Handle step2.html - Verify 3rd party cookie access
   * This page checks if the cookies set in step1 are accessible
   */
  async handleStep2(req: Request, res: Response): Promise<void> {
    try {
      // No template replacement needed for step2
      const html = step2HTML

      res.statusCode = 200
      res.setHeader('Content-Type', 'text/html; charset=utf-8')
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
      res.setHeader('Pragma', 'no-cache')
      res.end(html)

      if (this.config.development?.enableLogging) {
        console.log('[3P Cookies] Step2 served')
      }
    } catch (error) {
      console.error('[3P Cookies] Error serving step2.html:', error)

      res.statusCode = 500
      res.setHeader('Content-Type', 'text/plain')
      res.end('Internal Server Error')
    }
  }

  /**
   * Handle login-status-iframe.html - Session status checking iframe
   * This is used by Keycloak-js to check authentication status in an iframe
   */
  async handleLoginStatusIframe(req: Request, res: Response): Promise<void> {
    try {
      // No template replacement needed for login-status-iframe
      const html = loginStatusIframeHTML

      res.statusCode = 200
      res.setHeader('Content-Type', 'text/html; charset=utf-8')
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
      res.setHeader('Pragma', 'no-cache')
      res.end(html)

      if (this.config.development?.enableLogging) {
        console.log('[Login Status Iframe] Served')
      }
    } catch (error) {
      console.error(
        '[Login Status Iframe] Error serving login-status-iframe.html:',
        error,
      )

      res.statusCode = 500
      res.setHeader('Content-Type', 'text/plain')
      res.end('Internal Server Error')
    }
  }
}

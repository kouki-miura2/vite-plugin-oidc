/**
 * PKCE (Proof Key for Code Exchange) utility functions
 * Implements RFC 7636 for OAuth 2.0 security enhancement
 */

import crypto from 'crypto'

export class PKCEUtil {
  /**
   * Verify PKCE code challenge against code verifier
   * @param codeVerifier The code verifier from the token request
   * @param codeChallenge The code challenge from the authorization request
   * @param method The code challenge method (only S256 supported)
   * @returns true if verification succeeds, false otherwise
   */
  static verifyCodeChallenge(
    codeVerifier: string,
    codeChallenge: string,
    method: string = 'S256',
  ): boolean {
    if (method !== 'S256') {
      return false
    }

    try {
      // Generate code challenge from verifier using S256 method
      const hash = crypto.createHash('sha256')
      hash.update(codeVerifier)
      const computedChallenge = hash.digest('base64url')

      // Compare with the original challenge
      return computedChallenge === codeChallenge
    } catch (error) {
      console.error('PKCE verification error:', error)
      return false
    }
  }

  /**
   * Generate a code verifier for testing purposes
   * @param length The length of the code verifier (43-128 characters)
   * @returns A base64url-encoded code verifier
   */
  static generateCodeVerifier(length: number = 128): string {
    if (length < 43 || length > 128) {
      throw new Error(
        'Code verifier length must be between 43 and 128 characters',
      )
    }

    const buffer = crypto.randomBytes(Math.ceil((length * 3) / 4))
    return buffer.toString('base64url').substring(0, length)
  }

  /**
   * Generate a code challenge from a code verifier
   * @param codeVerifier The code verifier
   * @param method The challenge method (only S256 supported)
   * @returns The base64url-encoded code challenge
   */
  static generateCodeChallenge(
    codeVerifier: string,
    method: string = 'S256',
  ): string {
    if (method !== 'S256') {
      throw new Error('Only S256 code challenge method is supported')
    }

    const hash = crypto.createHash('sha256')
    hash.update(codeVerifier)
    return hash.digest('base64url')
  }

  /**
   * Validate code verifier format according to RFC 7636
   * @param codeVerifier The code verifier to validate
   * @returns true if valid, false otherwise
   */
  static isValidCodeVerifier(codeVerifier: string): boolean {
    // RFC 7636: code verifier must be 43-128 characters long
    if (codeVerifier.length < 43 || codeVerifier.length > 128) {
      return false
    }

    // Must contain only unreserved characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    const validPattern = /^[A-Za-z0-9\-._~]+$/
    return validPattern.test(codeVerifier)
  }
}

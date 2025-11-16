/**
 * Test helper for generating valid PKCE values
 */

import { PKCEUtil } from '../../src/utils/PKCEUtil.js'

export class PKCETestHelper {
  /**
   * Generate a valid PKCE code verifier and challenge pair for testing
   */
  static generateValidPKCEPair(): {
    codeVerifier: string
    codeChallenge: string
  } {
    const codeVerifier = PKCEUtil.generateCodeVerifier(128)
    const codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier)

    return {
      codeVerifier,
      codeChallenge,
    }
  }

  /**
   * Get a fixed valid PKCE pair for consistent testing
   */
  static getFixedValidPKCEPair(): {
    codeVerifier: string
    codeChallenge: string
  } {
    // Use a fixed code verifier for consistent tests
    const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    const codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier)

    return {
      codeVerifier,
      codeChallenge,
    }
  }

  /**
   * Get an invalid code challenge for testing error scenarios
   */
  static getInvalidCodeChallenge(): string {
    return 'invalid_challenge'
  }

  /**
   * Get an invalid code verifier for testing error scenarios
   */
  static getInvalidCodeVerifier(): string {
    return 'invalid_verifier'
  }
}

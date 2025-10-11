/**
 * Tests for PKCEUtil
 */

import { describe, it, expect } from 'vitest';
import { PKCEUtil } from "../../../src/utils/PKCEUtil.js";

describe('PKCEUtil', () => {
  describe('verifyCodeChallenge', () => {
    it('should verify valid code challenge and verifier pair', () => {
      // Test vector from RFC 7636
      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const codeChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      
      const result = PKCEUtil.verifyCodeChallenge(codeVerifier, codeChallenge, 'S256');
      expect(result).toBe(true);
    });

    it('should reject invalid code verifier', () => {
      const invalidCodeVerifier = 'invalid_verifier';
      const codeChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      
      const result = PKCEUtil.verifyCodeChallenge(invalidCodeVerifier, codeChallenge, 'S256');
      expect(result).toBe(false);
    });

    it('should reject unsupported challenge method', () => {
      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const codeChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      
      const result = PKCEUtil.verifyCodeChallenge(codeVerifier, codeChallenge, 'plain');
      expect(result).toBe(false);
    });
  });

  describe('generateCodeChallenge', () => {
    it('should generate correct code challenge from verifier', () => {
      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const expectedChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      
      const result = PKCEUtil.generateCodeChallenge(codeVerifier, 'S256');
      expect(result).toBe(expectedChallenge);
    });

    it('should throw error for unsupported method', () => {
      const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      
      expect(() => {
        PKCEUtil.generateCodeChallenge(codeVerifier, 'plain');
      }).toThrow('Only S256 code challenge method is supported');
    });
  });

  describe('generateCodeVerifier', () => {
    it('should generate code verifier of correct length', () => {
      const verifier = PKCEUtil.generateCodeVerifier(128);
      expect(verifier.length).toBe(128);
    });

    it('should generate code verifier with valid characters', () => {
      const verifier = PKCEUtil.generateCodeVerifier(64);
      const validPattern = /^[A-Za-z0-9\-._~]+$/;
      expect(validPattern.test(verifier)).toBe(true);
    });

    it('should throw error for invalid length', () => {
      expect(() => {
        PKCEUtil.generateCodeVerifier(42); // Too short
      }).toThrow('Code verifier length must be between 43 and 128 characters');

      expect(() => {
        PKCEUtil.generateCodeVerifier(129); // Too long
      }).toThrow('Code verifier length must be between 43 and 128 characters');
    });
  });

  describe('isValidCodeVerifier', () => {
    it('should validate correct code verifier', () => {
      const validVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      expect(PKCEUtil.isValidCodeVerifier(validVerifier)).toBe(true);
    });

    it('should reject code verifier that is too short', () => {
      const shortVerifier = 'short';
      expect(PKCEUtil.isValidCodeVerifier(shortVerifier)).toBe(false);
    });

    it('should reject code verifier that is too long', () => {
      const longVerifier = 'a'.repeat(129);
      expect(PKCEUtil.isValidCodeVerifier(longVerifier)).toBe(false);
    });

    it('should reject code verifier with invalid characters', () => {
      const invalidVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk!@#';
      expect(PKCEUtil.isValidCodeVerifier(invalidVerifier)).toBe(false);
    });
  });
});
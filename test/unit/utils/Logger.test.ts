/**
 * Unit tests for Logger
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Logger, LogLevel, logger } from '../../../src/utils/Logger.js'
import type { OIDCError } from '../../../src/types/oidc.js'

describe('Logger', () => {
  let testLogger: Logger

  beforeEach(() => {
    // Create a fresh logger instance for testing
    testLogger = Logger.getInstance()
    testLogger.clearLogs()
    testLogger.configure({
      logLevel: LogLevel.DEBUG,
      enableConsoleOutput: false, // Disable console output for tests
    })
  })

  describe('basic logging', () => {
    it('should log error messages', () => {
      testLogger.error('Test error message', { endpoint: '/test' })

      const logs = testLogger.getRecentLogs(1)
      expect(logs).toHaveLength(1)
      expect(logs[0].level).toBe(LogLevel.ERROR)
      expect(logs[0].message).toBe('Test error message')
      expect(logs[0].context?.endpoint).toBe('/test')
    })

    it('should log warning messages', () => {
      testLogger.warn('Test warning message')

      const logs = testLogger.getRecentLogs(1)
      expect(logs).toHaveLength(1)
      expect(logs[0].level).toBe(LogLevel.WARN)
      expect(logs[0].message).toBe('Test warning message')
    })

    it('should log info messages', () => {
      testLogger.info('Test info message')

      const logs = testLogger.getRecentLogs(1)
      expect(logs).toHaveLength(1)
      expect(logs[0].level).toBe(LogLevel.INFO)
      expect(logs[0].message).toBe('Test info message')
    })

    it('should log debug messages', () => {
      testLogger.debug('Test debug message')

      const logs = testLogger.getRecentLogs(1)
      expect(logs).toHaveLength(1)
      expect(logs[0].level).toBe(LogLevel.DEBUG)
      expect(logs[0].message).toBe('Test debug message')
    })
  })

  describe('log level filtering', () => {
    it('should filter logs based on log level', () => {
      testLogger.configure({ logLevel: LogLevel.WARN })

      testLogger.debug('Debug message')
      testLogger.info('Info message')
      testLogger.warn('Warning message')
      testLogger.error('Error message')

      const logs = testLogger.getRecentLogs()
      expect(logs).toHaveLength(2)
      expect(logs[0].level).toBe(LogLevel.WARN)
      expect(logs[1].level).toBe(LogLevel.ERROR)
    })
  })

  describe('OIDC-specific logging', () => {
    it('should log authorization requests', () => {
      testLogger.logAuthorizationRequest({
        clientId: 'test_client',
        redirectUri: 'https://example.com/callback',
        responseType: 'code',
        scope: 'openid profile',
        state: 'xyz',
        codeChallenge: 'challenge123',
        requestId: 'req_123',
      })

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].message).toBe('Authorization request received')
      expect(logs[0].context?.endpoint).toBe('/authorize')
      expect(logs[0].context?.clientId).toBe('test_client')
      expect(logs[0].context?.scope).toBe('openid profile')
    })

    it('should log authorization success', () => {
      testLogger.logAuthorizationSuccess({
        clientId: 'test_client',
        userId: 'user123',
        authorizationCode: 'code123',
        requestId: 'req_123',
      })

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].message).toBe('Authorization successful')
      expect(logs[0].context?.userId).toBe('user123')
      expect(logs[0].context?.authorizationCode).toBe('[GENERATED]')
    })

    it('should log authorization errors', () => {
      const error: OIDCError = {
        error: 'invalid_request',
        error_description: 'Missing client_id parameter',
      }

      testLogger.logAuthorizationError(error, {
        clientId: 'test_client',
        redirectUri: 'https://example.com/callback',
        requestId: 'req_123',
      })

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].level).toBe(LogLevel.ERROR)
      expect(logs[0].message).toBe('Authorization request failed')
      expect(logs[0].context?.errorCode).toBe('invalid_request')
      expect(logs[0].error).toBe(error)
    })

    it('should log token requests', () => {
      testLogger.logTokenRequest({
        clientId: 'test_client',
        grantType: 'authorization_code',
        authorizationCode: 'code123',
        requestId: 'req_123',
      })

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].message).toBe('Token request received')
      expect(logs[0].context?.endpoint).toBe('/token')
      expect(logs[0].context?.grantType).toBe('authorization_code')
    })

    it('should log token success', () => {
      testLogger.logTokenSuccess({
        clientId: 'test_client',
        userId: 'user123',
        scope: 'openid profile',
        requestId: 'req_123',
      })

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].message).toBe('Token exchange successful')
      expect(logs[0].context?.accessToken).toBe('[GENERATED]')
      expect(logs[0].context?.idToken).toBe('[GENERATED]')
    })

    it('should log userinfo requests', () => {
      testLogger.logUserInfoRequest({
        userId: 'user123',
        clientId: 'test_client',
        scope: 'openid profile',
        requestId: 'req_123',
      })

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].message).toBe('UserInfo request received')
      expect(logs[0].context?.endpoint).toBe('/userinfo')
    })
  })

  describe('system logging', () => {
    it('should log startup information', () => {
      testLogger.logStartup({
        basePath: '/oidc',
        issuer: 'http://localhost:5173/oidc',
        endpoints: ['/authorize', '/token', '/userinfo'],
        clientCount: 2,
        userCount: 3,
      })

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].message).toBe('OIDC Plugin initialized')
      expect(logs[0].context?.basePath).toBe('/oidc')
      expect(logs[0].context?.clientCount).toBe(2)
      expect(logs[0].context?.userCount).toBe(3)
    })

    it('should log shutdown', () => {
      testLogger.logShutdown()

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].message).toBe('OIDC Plugin shutting down')
    })

    it('should log production warnings', () => {
      testLogger.logProductionWarning()

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].level).toBe(LogLevel.WARN)
      expect(logs[0].message).toContain('production mode')
      expect(logs[0].context?.environment).toBe('production')
    })
  })

  describe('validation error logging', () => {
    it('should log validation errors with suggestions', () => {
      const error: OIDCError = {
        error: 'invalid_request',
        error_description: 'Missing client_id parameter',
      }

      testLogger.logValidationError(error, {
        endpoint: '/authorize',
        parameter: 'client_id',
        expectedFormat: 'string',
        requestId: 'req_123',
      })

      const logs = testLogger.getRecentLogs(1)
      expect(logs[0].level).toBe(LogLevel.ERROR)
      expect(logs[0].message).toContain('Parameter validation failed')
      expect(logs[0].context?.parameter).toBe('client_id')
      expect(logs[0].context?.suggestion).toBeDefined()
    })
  })

  describe('log management', () => {
    it('should retrieve recent logs', () => {
      testLogger.info('Message 1')
      testLogger.info('Message 2')
      testLogger.info('Message 3')

      const logs = testLogger.getRecentLogs(2)
      expect(logs).toHaveLength(2)
      expect(logs[0].message).toBe('Message 2')
      expect(logs[1].message).toBe('Message 3')
    })

    it('should filter logs by endpoint', () => {
      testLogger.info('Auth message', { endpoint: '/authorize' })
      testLogger.info('Token message', { endpoint: '/token' })
      testLogger.info('Auth message 2', { endpoint: '/authorize' })

      const authLogs = testLogger.getLogsForEndpoint('/authorize')
      expect(authLogs).toHaveLength(2)
      expect(authLogs[0].message).toBe('Auth message')
      expect(authLogs[1].message).toBe('Auth message 2')
    })

    it('should clear logs', () => {
      testLogger.info('Message 1')
      testLogger.info('Message 2')

      expect(testLogger.getRecentLogs()).toHaveLength(2)

      testLogger.clearLogs()
      expect(testLogger.getRecentLogs()).toHaveLength(0)
    })

    it('should limit log entries', () => {
      testLogger.configure({ maxLogEntries: 3 })

      testLogger.info('Message 1')
      testLogger.info('Message 2')
      testLogger.info('Message 3')
      testLogger.info('Message 4')
      testLogger.info('Message 5')

      const logs = testLogger.getRecentLogs()
      expect(logs).toHaveLength(3)
      expect(logs[0].message).toBe('Message 3')
      expect(logs[2].message).toBe('Message 5')
    })
  })

  describe('console output', () => {
    it('should output to console when enabled', () => {
      const consoleSpy = vi.spyOn(console, 'info').mockImplementation(() => {})

      testLogger.configure({ enableConsoleOutput: true })
      testLogger.info('Test message')

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('[INFO] [vite-plugin-oidc] Test message'),
      )

      consoleSpy.mockRestore()
    })

    it('should not output to console when disabled', () => {
      const consoleSpy = vi.spyOn(console, 'info').mockImplementation(() => {})

      testLogger.configure({ enableConsoleOutput: false })
      testLogger.info('Test message')

      expect(consoleSpy).not.toHaveBeenCalled()

      consoleSpy.mockRestore()
    })
  })

  describe('singleton behavior', () => {
    it('should return the same instance', () => {
      const instance1 = Logger.getInstance()
      const instance2 = Logger.getInstance()

      expect(instance1).toBe(instance2)
      expect(instance1).toBe(logger)
    })
  })
})

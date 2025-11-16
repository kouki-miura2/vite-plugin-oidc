/**
 * Structured logging utility for OIDC operations
 * Provides clear error messages and debugging information for developers
 */

import type { OIDCError } from '../types/oidc.js'

export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

export interface LogContext {
  endpoint?: string
  clientId?: string
  userId?: string
  requestId?: string
  timestamp?: number
  [key: string]: any
}

export interface LogEntry {
  level: LogLevel
  message: string
  context?: LogContext
  error?: Error | OIDCError
  timestamp: number
}

export class Logger {
  private static instance: Logger
  private logLevel: LogLevel = LogLevel.INFO
  private enableConsoleOutput: boolean = true
  private logEntries: LogEntry[] = []
  private maxLogEntries: number = 1000

  private constructor() {}

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger()
    }
    return Logger.instance
  }

  /**
   * Configure logger settings
   */
  configure(options: {
    logLevel?: LogLevel
    enableConsoleOutput?: boolean
    maxLogEntries?: number
  }): void {
    if (options.logLevel !== undefined) {
      this.logLevel = options.logLevel
    }
    if (options.enableConsoleOutput !== undefined) {
      this.enableConsoleOutput = options.enableConsoleOutput
    }
    if (options.maxLogEntries !== undefined) {
      this.maxLogEntries = options.maxLogEntries
    }
  }

  /**
   * Log error message
   */
  error(
    message: string,
    context?: LogContext,
    error?: Error | OIDCError
  ): void {
    this.log(LogLevel.ERROR, message, context, error)
  }

  /**
   * Log warning message
   */
  warn(message: string, context?: LogContext): void {
    this.log(LogLevel.WARN, message, context)
  }

  /**
   * Log info message
   */
  info(message: string, context?: LogContext): void {
    this.log(LogLevel.INFO, message, context)
  }

  /**
   * Log debug message
   */
  debug(message: string, context?: LogContext): void {
    this.log(LogLevel.DEBUG, message, context)
  }

  /**
   * Log OIDC authorization request
   */
  logAuthorizationRequest(context: {
    clientId: string
    redirectUri: string
    responseType: string
    scope?: string
    state?: string
    codeChallenge: string
    requestId?: string
  }): void {
    this.info('Authorization request received', {
      endpoint: '/authorize',
      clientId: context.clientId,
      redirectUri: context.redirectUri,
      responseType: context.responseType,
      scope: context.scope,
      state: context.state,
      codeChallenge: context.codeChallenge ? '[PRESENT]' : '[MISSING]',
      requestId: context.requestId,
    })
  }

  /**
   * Log OIDC authorization success
   */
  logAuthorizationSuccess(context: {
    clientId: string
    userId: string
    authorizationCode: string
    requestId?: string
  }): void {
    this.info('Authorization successful', {
      endpoint: '/authorize',
      clientId: context.clientId,
      userId: context.userId,
      authorizationCode: '[GENERATED]',
      requestId: context.requestId,
    })
  }

  /**
   * Log OIDC authorization error
   */
  logAuthorizationError(
    error: OIDCError,
    context: {
      clientId?: string
      redirectUri?: string
      requestId?: string
    }
  ): void {
    this.error(
      'Authorization request failed',
      {
        endpoint: '/authorize',
        clientId: context.clientId,
        redirectUri: context.redirectUri,
        requestId: context.requestId,
        errorCode: error.error,
        errorDescription: error.error_description,
      },
      error
    )
  }

  /**
   * Log token request
   */
  logTokenRequest(context: {
    clientId: string
    grantType: string
    authorizationCode: string
    requestId?: string
  }): void {
    this.info('Token request received', {
      endpoint: '/token',
      clientId: context.clientId,
      grantType: context.grantType,
      authorizationCode: '[PRESENT]',
      requestId: context.requestId,
    })
  }

  /**
   * Log token exchange success
   */
  logTokenSuccess(context: {
    clientId: string
    userId: string
    scope?: string
    requestId?: string
  }): void {
    this.info('Token exchange successful', {
      endpoint: '/token',
      clientId: context.clientId,
      userId: context.userId,
      scope: context.scope,
      accessToken: '[GENERATED]',
      idToken: '[GENERATED]',
      requestId: context.requestId,
    })
  }

  /**
   * Log token error
   */
  logTokenError(
    error: OIDCError,
    context: {
      clientId?: string
      grantType?: string
      requestId?: string
    }
  ): void {
    this.error(
      'Token request failed',
      {
        endpoint: '/token',
        clientId: context.clientId,
        grantType: context.grantType,
        requestId: context.requestId,
        errorCode: error.error,
        errorDescription: error.error_description,
      },
      error
    )
  }

  /**
   * Log userinfo request
   */
  logUserInfoRequest(context: {
    userId?: string
    clientId?: string
    scope?: string
    requestId?: string
  }): void {
    this.info('UserInfo request received', {
      endpoint: '/userinfo',
      userId: context.userId,
      clientId: context.clientId,
      scope: context.scope,
      requestId: context.requestId,
    })
  }

  /**
   * Log userinfo success
   */
  logUserInfoSuccess(context: {
    userId: string
    clientId?: string
    requestId?: string
  }): void {
    this.info('UserInfo request successful', {
      endpoint: '/userinfo',
      userId: context.userId,
      clientId: context.clientId,
      requestId: context.requestId,
    })
  }

  /**
   * Log userinfo error
   */
  logUserInfoError(
    error: OIDCError,
    context: {
      userId?: string
      clientId?: string
      requestId?: string
    }
  ): void {
    this.error(
      'UserInfo request failed',
      {
        endpoint: '/userinfo',
        userId: context.userId,
        clientId: context.clientId,
        requestId: context.requestId,
        errorCode: error.error,
        errorDescription: error.error_description,
      },
      error
    )
  }

  /**
   * Log system startup
   */
  logStartup(context: {
    basePath: string
    issuer: string
    endpoints: string[]
    clientCount: number
    userCount: number
  }): void {
    this.info('OIDC Plugin initialized', {
      basePath: context.basePath,
      issuer: context.issuer,
      endpoints: context.endpoints,
      clientCount: context.clientCount,
      userCount: context.userCount,
    })
  }

  /**
   * Log system shutdown
   */
  logShutdown(): void {
    this.info('OIDC Plugin shutting down', {
      totalRequests: this.logEntries.filter((e) => e.context?.endpoint).length,
    })
  }

  /**
   * Log production warning
   */
  logProductionWarning(): void {
    this.warn(
      '⚠️  vite-plugin-oidc is running in production mode. This plugin is intended for development only!',
      {
        environment: 'production',
        recommendation: 'Use a proper OIDC provider in production',
      }
    )
  }

  /**
   * Log validation error with helpful suggestions
   */
  logValidationError(
    error: OIDCError,
    context: LogContext & {
      parameter?: string
      expectedFormat?: string
      suggestion?: string
    }
  ): void {
    const message = `Parameter validation failed: ${error.error_description}`
    const enhancedContext = {
      ...context,
      errorCode: error.error,
      parameter: context.parameter,
      expectedFormat: context.expectedFormat,
      suggestion:
        context.suggestion ||
        this.getSuggestionForError(error.error, context.parameter),
    }

    this.error(message, enhancedContext, error)
  }

  /**
   * Get recent log entries for debugging
   */
  getRecentLogs(count: number = 50): LogEntry[] {
    return this.logEntries.slice(-count)
  }

  /**
   * Get logs for specific endpoint
   */
  getLogsForEndpoint(endpoint: string, count: number = 50): LogEntry[] {
    return this.logEntries
      .filter((entry) => entry.context?.endpoint === endpoint)
      .slice(-count)
  }

  /**
   * Clear all log entries
   */
  clearLogs(): void {
    this.logEntries = []
  }

  /**
   * Internal logging method
   */
  private log(
    level: LogLevel,
    message: string,
    context?: LogContext,
    error?: Error | OIDCError
  ): void {
    if (level > this.logLevel) {
      return
    }

    const logEntry: LogEntry = {
      level,
      message,
      context: {
        ...context,
        timestamp: Date.now(),
      },
      error,
      timestamp: Date.now(),
    }

    // Add to log entries
    this.logEntries.push(logEntry)

    // Trim log entries if needed
    if (this.logEntries.length > this.maxLogEntries) {
      this.logEntries = this.logEntries.slice(-this.maxLogEntries)
    }

    // Console output
    if (this.enableConsoleOutput) {
      this.outputToConsole(logEntry)
    }
  }

  /**
   * Output log entry to console
   */
  private outputToConsole(entry: LogEntry): void {
    const timestamp = new Date(entry.timestamp).toISOString()
    const levelName = LogLevel[entry.level]
    const prefix = `[${timestamp}] [${levelName}] [vite-plugin-oidc]`

    let output = `${prefix} ${entry.message}`

    if (entry.context && Object.keys(entry.context).length > 0) {
      const contextStr = JSON.stringify(entry.context, null, 2)
      output += `\n  Context: ${contextStr}`
    }

    if (entry.error) {
      if ('error' in entry.error) {
        // OIDC Error
        output += `\n  OIDC Error: ${entry.error.error}`
        if (entry.error.error_description) {
          output += ` - ${entry.error.error_description}`
        }
      } else {
        // Standard Error
        output += `\n  Error: ${entry.error.message}`
        if (entry.error.stack) {
          output += `\n  Stack: ${entry.error.stack}`
        }
      }
    }

    switch (entry.level) {
      case LogLevel.ERROR:
        console.error(output)
        break
      case LogLevel.WARN:
        console.warn(output)
        break
      case LogLevel.INFO:
        console.info(output)
        break
      case LogLevel.DEBUG:
        console.debug(output)
        break
    }
  }

  /**
   * Get helpful suggestion for common errors
   */
  private getSuggestionForError(errorCode: string, parameter?: string): string {
    switch (errorCode) {
      case 'invalid_request':
        if (parameter === 'code_challenge') {
          return 'Ensure code_challenge is base64url-encoded and 43-128 characters long'
        }
        if (parameter === 'redirect_uri') {
          return 'Ensure redirect_uri is registered for this client and uses HTTPS (or HTTP for localhost)'
        }
        return 'Check that all required parameters are present and properly formatted'

      case 'unauthorized_client':
        return 'Verify that the client_id is registered in the plugin configuration'

      case 'unsupported_response_type':
        return 'Only response_type=code is supported (Authorization Code Flow)'

      case 'invalid_scope':
        return 'Supported scopes are: openid, profile, email, address, phone'

      case 'invalid_grant':
        return 'Check that the authorization code is valid and not expired, and code_verifier matches the original code_challenge'

      case 'unsupported_grant_type':
        return 'Only grant_type=authorization_code is supported'

      case 'invalid_client':
        return 'Verify that the client_id exists in the plugin configuration'

      case 'invalid_token':
        return 'Ensure the access token is valid, not expired, and properly formatted as a Bearer token'

      default:
        return 'Check the OIDC specification for parameter requirements'
    }
  }
}

// Export singleton instance
export const logger = Logger.getInstance()

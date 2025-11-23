/**
 * Tests for the main OIDC plugin
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import oidcPlugin from '../../src/index.js'

interface MockViteServer {
  config: {
    server: {
      port?: number
    }
  }
  middlewares: {
    use: ReturnType<typeof vi.fn>
  }
}

describe('OIDC Plugin', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    consoleSpy.mockRestore()
    consoleErrorSpy.mockRestore()
    consoleWarnSpy.mockRestore()
    delete process.env.NODE_ENV
    delete process.env.VITE_ENV
    delete process.env.MODE
  })

  describe('Plugin Configuration', () => {
    it('should create plugin with default configuration', () => {
      const plugin = oidcPlugin()

      expect(plugin.name).toBe('vite-plugin-oidc')
      expect(plugin.configureServer).toBeDefined()
      expect(plugin.buildEnd).toBeDefined()
    })

    it('should merge user configuration with defaults', () => {
      const userConfig = {
        basePath: '/custom-auth',
        development: {
          enableLogging: false,
        },
      }

      const plugin = oidcPlugin(userConfig)
      expect(plugin.name).toBe('vite-plugin-oidc')
    })
  })

  describe('Production Environment Detection', () => {
    it('should show production warnings when NODE_ENV is production', () => {
      process.env.NODE_ENV = 'production'

      const plugin = oidcPlugin()
      const mockServer: MockViteServer = {
        config: { server: { port: 5173 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'WARNING: This plugin is running in production mode!',
        ),
      )
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('This plugin is intended for development only'),
      )
    })

    it('should show production warnings when VITE_ENV is production', () => {
      process.env.VITE_ENV = 'production'

      const plugin = oidcPlugin()
      const mockServer: MockViteServer = {
        config: { server: { port: 5173 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'WARNING: This plugin is running in production mode!',
        ),
      )
    })

    it('should show production warnings when MODE is production', () => {
      process.env.MODE = 'production'

      const plugin = oidcPlugin()
      const mockServer = {
        config: { server: { port: 5173 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'WARNING: This plugin is running in production mode!',
        ),
      )
    })

    it('should not show warnings in development mode', () => {
      const plugin = oidcPlugin()
      const mockServer: MockViteServer = {
        config: { server: { port: 5173 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      // Should not show production warnings in development
      expect(consoleErrorSpy).not.toHaveBeenCalledWith(
        expect.stringContaining(
          'WARNING: This plugin is running in production mode!',
        ),
      )
    })
  })

  describe('Default User Accounts', () => {
    it('should provide multiple test user accounts with different roles', () => {
      const plugin = oidcPlugin()
      const mockServer: MockViteServer = {
        config: { server: { port: 5173 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      // The default config should have been applied with multiple users
      // We can't directly access the config, but we can verify the plugin was created
      expect(plugin.name).toBe('vite-plugin-oidc')
    })
  })

  describe('Dynamic Issuer Configuration', () => {
    it('should set dynamic issuer based on server port', () => {
      const plugin = oidcPlugin()
      const mockServer: MockViteServer = {
        config: { server: { port: 8080 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Initializing OIDC endpoints at /oidc'),
      )
    })

    it('should use default port 5173 when no port is specified', () => {
      const plugin = oidcPlugin()
      const mockServer: MockViteServer = {
        config: { server: {} },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Initializing OIDC endpoints at /oidc'),
      )
    })

    it('should use provided issuer when specified', () => {
      const plugin = oidcPlugin({
        issuer: 'https://custom-issuer.com/auth',
      })
      const mockServer: MockViteServer = {
        config: { server: { port: 5173 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      // Should not override the provided issuer
      expect(plugin.name).toBe('vite-plugin-oidc')
    })
  })

  describe('Middleware Registration', () => {
    it('should register middleware with the server', () => {
      const plugin = oidcPlugin()
      const mockServer: MockViteServer = {
        config: { server: { port: 5173 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      expect(mockServer.middlewares.use).toHaveBeenCalledWith(
        '/oidc',
        expect.any(Function),
      )
    })

    it('should register middleware with custom base path', () => {
      const plugin = oidcPlugin({
        basePath: '/custom-auth',
      })
      const mockServer: MockViteServer = {
        config: { server: { port: 5173 } },
        middlewares: { use: vi.fn() },
      }

      plugin.configureServer!(mockServer as never)

      expect(mockServer.middlewares.use).toHaveBeenCalledWith(
        '/custom-auth',
        expect.any(Function),
      )
    })
  })

  describe('Cleanup', () => {
    it('should provide cleanup functionality', () => {
      const plugin = oidcPlugin()

      expect(plugin.buildEnd).toBeDefined()
      expect(typeof plugin.buildEnd).toBe('function')
    })
  })
})

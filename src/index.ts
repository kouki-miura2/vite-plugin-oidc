/**
 * Main entry point for vite-plugin-oidc
 */

import type { OIDCPluginConfig } from './types/index.js';
import { createOIDCMiddleware } from './middleware/index.js';

// Define minimal types to avoid vite dependency in build
interface ViteDevServer {
    config: {
        server: {
            port?: number;
        };
    };
    middlewares: any;
}

interface Plugin {
    name: string;
    configureServer?: (server: ViteDevServer) => void;
    buildEnd?: () => void;
}

/**
 * Default configuration for the OIDC plugin
 */
const defaultConfig: Required<OIDCPluginConfig> = {
    basePath: '/oidc',
    issuer: '', // Will be set dynamically based on server
    jwt: {
        algorithm: 'HS256',
        secret: 'dev-secret-key-change-in-production'
    },
    users: [],
    clients: [],
    tokenExpiration: {
        authorizationCode: 600, // 10 minutes
        accessToken: 3600, // 1 hour
        idToken: 3600 // 1 hour
    },
    development: {
        enableLogging: true,
        showWarnings: true
    },
    loginUI: {
        title: 'OIDC Login'
    }
};



/**
 * Creates the OIDC Vite plugin
 */
export default function oidcPlugin(userConfig: OIDCPluginConfig = {}): Plugin {
    // Merge default config with user config
    const config = {
        ...defaultConfig,
        ...userConfig
    };
    let middleware: any = null;

    return {
        name: 'vite-plugin-oidc',
        configureServer(server: ViteDevServer) {
            // Check for production environment and show warnings
            const isProduction = process.env.NODE_ENV === 'production' ||
                process.env.VITE_ENV === 'production' ||
                process.env.MODE === 'production';

            if (isProduction && config.development?.showWarnings) {
                console.error('⚠️  [vite-plugin-oidc] WARNING: This plugin is running in production mode!');
                console.error('⚠️  [vite-plugin-oidc] This plugin is intended for development only and should NOT be used in production.');
                console.error('⚠️  [vite-plugin-oidc] Please remove this plugin from your production build configuration.');
                console.error('⚠️  [vite-plugin-oidc] Using mock OIDC in production poses serious security risks.');
            }

            if (config.development?.enableLogging) {
                console.log(`[vite-plugin-oidc] Initializing OIDC endpoints at ${config.basePath}`);
                if (isProduction) {
                    console.log(`[vite-plugin-oidc] Environment: PRODUCTION (⚠️  NOT RECOMMENDED)`);
                } else {
                    console.log(`[vite-plugin-oidc] Environment: Development`);
                }
            }

            if (config.development?.showWarnings && !isProduction) {
                console.warn('[vite-plugin-oidc] This plugin is for development only. Do not use in production!');
            }

            // Set dynamic issuer if not provided
            if (!userConfig.issuer) {
                const port = server.config.server.port || 5173;
                config.issuer = `http://localhost:${port}${config.basePath}`;
            }

            // Create and register OIDC middleware
            middleware = createOIDCMiddleware(config);
            server.middlewares.use(config.basePath, middleware);

            // Store cleanup function for buildEnd hook
            // Avoid process signal handlers that can interfere with Vite's shutdown
            // Let Vite handle the lifecycle through buildEnd hook instead

            if (config.development?.enableLogging) {
                console.log(`[vite-plugin-oidc] OIDC endpoints registered:`);
                console.log(`  - Discovery: ${config.issuer}/.well-known/openid-configuration`);
                console.log(`  - Authorization: ${config.issuer}/authorize`);
                console.log(`  - Token: ${config.issuer}/token`);
                console.log(`  - UserInfo: ${config.issuer}/userinfo`);
                console.log(`  - JWKS: ${config.issuer}/jwks`);
                console.log(`  - Login UI: ${config.issuer}/login`);
            }
        },
        buildEnd() {
            // Cleanup resources when plugin is destroyed
            try {
                if (config.development?.enableLogging) {
                    console.log('[vite-plugin-oidc] Plugin shutting down, cleaning up resources...');
                }

                if (middleware && typeof middleware.cleanup === 'function') {
                    middleware.cleanup();
                }

                if (config.development?.enableLogging) {
                    console.log('[vite-plugin-oidc] Plugin cleanup completed successfully');
                }
            } catch (error) {
                console.error('[vite-plugin-oidc] Error during plugin cleanup:', error);
            }
        }
    };
}

// Export types for consumers
export type { OIDCPluginConfig } from './types/index.js';
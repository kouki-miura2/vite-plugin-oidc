/**
 * Test configuration helper for OIDC plugin tests
 */

import type { OIDCPluginConfig } from '../../src/types/index.js'

export function getTestConfig(
  overrides: Partial<OIDCPluginConfig> = {}
): OIDCPluginConfig {
  const defaultTestConfig: OIDCPluginConfig = {
    users: [
      {
        id: 'johndoe',
        username: 'johndoe',
        password: 'password123',
        profile: {
          sub: 'johndoe',
          name: 'John Doe',
          given_name: 'John',
          family_name: 'Doe',
          email: 'john.doe@example.com',
          email_verified: true,
          username: 'johndoe',
        },
      },
      {
        id: 'testuser',
        username: 'testuser',
        password: 'password123',
        profile: {
          sub: 'testuser',
          name: 'Test User',
          given_name: 'Test',
          family_name: 'User',
          email: 'test@example.com',
          email_verified: true,
          username: 'testuser',
        },
      },
      {
        id: 'admin',
        username: 'admin',
        password: 'admin123',
        profile: {
          sub: '2',
          name: 'Admin User',
          given_name: 'Admin',
          family_name: 'User',
          email: 'admin@example.com',
          email_verified: true,
          username: 'admin',
          role: 'admin',
        },
      },
    ],
    clients: [
      {
        client_id: 'test_client',
        redirect_uris: [
          'http://localhost:5173/',
          'http://localhost:3000/callback',
        ],
        response_types: ['code'],
        grant_types: ['authorization_code'],
      },
    ],
    loginUI: {
      title: 'Test Client',
    },
    development: {
      enableLogging: false,
    },
  }

  return {
    ...defaultTestConfig,
    ...overrides,
    // Merge arrays properly
    users: [...(defaultTestConfig.users || []), ...(overrides.users || [])],
    clients: [
      ...(defaultTestConfig.clients || []),
      ...(overrides.clients || []),
    ],
  }
}

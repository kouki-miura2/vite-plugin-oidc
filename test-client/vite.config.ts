import { defineConfig } from 'vite'
import oidc from 'vite-plugin-oidc'

export default defineConfig({
  plugins: [
    oidc({
      basePath: '/realms/myrealm',
      clients: [
        {
          client_id: 'test-client',
          redirect_uris: ['http://localhost:5173/'],
          response_types: ['code'],
          grant_types: ['authorization_code'],
        },
      ],
      users: [
        {
          id: 'johndoe',
          username: 'johndoe',
          password: 'password123',
          profile: {
            sub: 'johndoe',
            name: 'John Doe',
            email: 'john.doe@example.com',
            email_verified: true,
          },
        },
      ],
    }),
  ],
})

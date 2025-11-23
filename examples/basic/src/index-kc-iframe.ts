import Keycloak from 'keycloak-js'

// Keycloak configuration using dedicated environment variables
const keycloakConfig = {
  url: import.meta.env.VITE_KEYCLOAK_AUTHORITY,
  realm: import.meta.env.VITE_KEYCLOAK_REALM,
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
}

console.log('Keycloak config will use:', {
  url: keycloakConfig.url,
  realm: keycloakConfig.realm,
  clientId: keycloakConfig.clientId,
  expectedTokenEndpoint: `${keycloakConfig.url}realms/${keycloakConfig.realm}/protocol/openid-connect/token`,
})

const keycloak = new Keycloak(keycloakConfig)

function el(id: string): HTMLElement {
  const e = document.getElementById(id)
  if (!e) throw new Error(`Element #${id} not found`)
  return e
}

async function checkAuthenticationStatus() {
  console.log('Checking authentication status...')
  console.log('Current keycloak state:', {
    authenticated: keycloak.authenticated,
    hasToken: !!keycloak.token,
    hasRefreshToken: !!keycloak.refreshToken,
    hasIdToken: !!keycloak.idToken,
    subject: keycloak.subject,
  })

  // If already authenticated, we're good
  if (keycloak.authenticated && keycloak.token) {
    console.log('Keycloak reports authenticated with token')
    return true
  }

  // If we have a token but not marked as authenticated, try to validate it
  if (keycloak.token && !keycloak.authenticated) {
    console.log(
      'Have token but not marked as authenticated, trying to validate...',
    )
    try {
      // Try to refresh/validate the token
      const refreshed = await keycloak.updateToken(5)
      console.log(
        'Token validation result:',
        refreshed,
        'authenticated:',
        keycloak.authenticated,
      )
      return keycloak.authenticated
    } catch (error) {
      console.log('Token validation failed:', error)
      return false
    }
  }

  // Check if we have tokens in localStorage but keycloak didn't load them
  const tokenKey = `kc-token-${keycloakConfig.realm}`
  const storedToken = localStorage.getItem(tokenKey)
  if (storedToken && !keycloak.token) {
    console.log(
      'Found stored token but keycloak didnt load it - this shouldnt happen',
    )
  }

  console.log('No valid authentication found')
  return false
}

function showUser() {
  const container = el('user-info')
  const loginBtn = el('login-btn') as HTMLButtonElement
  const logoutBtn = el('logout-btn') as HTMLButtonElement

  console.log('showUser called - authenticated:', keycloak.authenticated)
  console.log('showUser - token exists:', !!keycloak.token)
  console.log('showUser - tokenParsed:', keycloak.tokenParsed)
  console.log('showUser - idTokenParsed:', keycloak.idTokenParsed)

  if (
    keycloak.authenticated &&
    (keycloak.tokenParsed || keycloak.idTokenParsed)
  ) {
    // Use ID token for user profile information (OIDC standard)
    const tokenData = keycloak.idTokenParsed || keycloak.tokenParsed
    const profile = {
      sub: keycloak.subject,
      name: tokenData?.name || tokenData?.preferred_username,
      email: tokenData?.email,
      email_verified: tokenData?.email_verified,
      preferred_username: tokenData?.preferred_username,
      given_name: tokenData?.given_name,
      family_name: tokenData?.family_name,
    }
    container.innerHTML = `<pre>${JSON.stringify(profile, null, 2)}</pre>`
    loginBtn.style.display = 'none'
    logoutBtn.style.display = 'inline-block'
  } else {
    container.textContent = 'Not signed in'
    loginBtn.style.display = 'inline-block'
    logoutBtn.style.display = 'none'
  }
}

async function init() {
  console.log('Keycloak config:', keycloakConfig)
  console.log('=== TESTING WITH checkLoginIframe: true (DEFAULT) ===')

  // Set up event listeners first, even if Keycloak init fails
  el('login-btn').addEventListener('click', () => {
    console.log('Login button clicked')
    try {
      keycloak.login({
        redirectUri:
          window.location.origin +
          import.meta.env.BASE_URL +
          'index-kc-iframe.html',
      })
    } catch (error) {
      console.error('Login error:', error)
    }
  })

  el('logout-btn').addEventListener('click', () => {
    console.log('Logout button clicked')
    try {
      keycloak.logout({
        redirectUri:
          window.location.origin +
          import.meta.env.BASE_URL +
          'index-kc-iframe.html',
      })
    } catch (error) {
      console.error('Logout error:', error)
    }
  })

  try {
    console.log('Initializing Keycloak...')

    // Set up Keycloak event listeners before initialization
    keycloak.onAuthSuccess = () => {
      console.log('Authentication successful event triggered')
      showUser()
    }

    keycloak.onAuthError = (error) => {
      console.error('Authentication error event triggered:', error)
      showUser()
    }

    keycloak.onAuthLogout = () => {
      console.log('User logged out event triggered')
      showUser()
    }

    keycloak.onTokenExpired = () => {
      console.log('Token expired, refreshing...')
      keycloak
        .updateToken(30)
        .then((refreshed) => {
          if (refreshed) {
            console.log('Token refreshed')
          } else {
            console.log('Token still valid')
          }
        })
        .catch((error) => {
          console.error('Failed to refresh token:', error)
          keycloak.login()
        })
    }

    // Check if we have authentication callback in URL fragment
    const hasAuthCallback = window.location.hash.includes('code=')
    console.log(
      'Has auth callback:',
      hasAuthCallback,
      'Hash:',
      window.location.hash,
    )

    let authenticated = false

    if (hasAuthCallback) {
      // Process authentication callback
      console.log('Processing authentication callback...')
      authenticated = await keycloak.init({
        pkceMethod: 'S256',
        checkLoginIframe: true, // Enable 3rd party cookie check
        enableLogging: true,
      })
    } else {
      // Check for existing tokens in localStorage first
      const tokenKey = `kc-token-${keycloakConfig.realm}`
      const refreshTokenKey = `kc-refreshToken-${keycloakConfig.realm}`
      const idTokenKey = `kc-idToken-${keycloakConfig.realm}`

      const storedToken = localStorage.getItem(tokenKey)
      const storedRefreshToken = localStorage.getItem(refreshTokenKey)
      const storedIdToken = localStorage.getItem(idTokenKey)

      console.log('Checking stored tokens:', {
        hasToken: !!storedToken,
        hasRefreshToken: !!storedRefreshToken,
        hasIdToken: !!storedIdToken,
      })

      if (storedToken || storedRefreshToken || storedIdToken) {
        // We have stored tokens, use check-sso to restore them
        console.log('Found stored tokens, using check-sso to restore session')
        authenticated = await keycloak.init({
          onLoad: 'check-sso',
          silentCheckSsoRedirectUri:
            window.location.origin +
            import.meta.env.BASE_URL +
            'silent-check-sso.html',
          pkceMethod: 'S256',
          checkLoginIframe: true, // Enable 3rd party cookie check
          enableLogging: true,
        })
      } else {
        // No stored tokens, just initialize
        console.log(
          'No stored tokens found, initializing without session check',
        )
        authenticated = await keycloak.init({
          onLoad: 'check-sso',
          pkceMethod: 'S256',
          checkLoginIframe: true, // Enable 3rd party cookie check
          enableLogging: true,
        })
      }
    }

    console.log(
      'Keycloak initialized successfully. Authenticated:',
      authenticated,
    )
    console.log('Keycloak instance:', keycloak)
    console.log('Keycloak token:', keycloak.token)
    console.log('Keycloak tokenParsed:', keycloak.tokenParsed)
    console.log('Keycloak idToken:', keycloak.idToken)
    console.log('Keycloak idTokenParsed:', keycloak.idTokenParsed)

    // Clean up URL after successful authentication
    if (window.location.hash.includes('code=')) {
      console.log('Cleaning up URL after authentication')
      window.history.replaceState({}, document.title, window.location.pathname)
    }

    // Perform additional authentication check
    const isAuthenticated = await checkAuthenticationStatus()
    console.log('Final authentication status:', isAuthenticated)

    // Show current user state
    showUser()

    // If we just processed an authentication callback, ensure UI is updated
    if (hasAuthCallback && authenticated) {
      console.log('Authentication callback completed, updating UI')
      // Give keycloak-js a moment to fully process the tokens
      setTimeout(() => {
        console.log('Delayed UI update after authentication callback')
        showUser()
      }, 100)
    }

    // Event listeners are already set up before initialization
  } catch (error) {
    console.error('Failed to initialize Keycloak:', error)
    const container = el('user-info')
    container.innerHTML = `<div style="color: red;">Failed to initialize Keycloak: ${error}</div>`

    // Still show the login button even if init fails
    showUser()
  }
}

init().catch((e) => console.error('Initialization error:', e))

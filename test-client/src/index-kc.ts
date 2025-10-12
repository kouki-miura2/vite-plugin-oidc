import Keycloak from 'keycloak-js'

// Keycloak configuration using dedicated environment variables
const keycloakConfig = {
    url: import.meta.env.VITE_KEYCLOAK_AUTHORITY,
    realm: import.meta.env.VITE_KEYCLOAK_REALM,
    clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
}

const keycloak = new Keycloak(keycloakConfig)

function el(id: string): HTMLElement {
    const e = document.getElementById(id)
    if (!e) throw new Error(`Element #${id} not found`)
    return e
}

function showUser() {
    const container = el('user-info')
    const loginBtn = el('login-btn') as HTMLButtonElement
    const logoutBtn = el('logout-btn') as HTMLButtonElement

    if (keycloak.authenticated) {
        const profile = {
            sub: keycloak.subject,
            name: keycloak.tokenParsed?.name || keycloak.tokenParsed?.preferred_username,
            email: keycloak.tokenParsed?.email,
            email_verified: keycloak.tokenParsed?.email_verified,
            preferred_username: keycloak.tokenParsed?.preferred_username,
            given_name: keycloak.tokenParsed?.given_name,
            family_name: keycloak.tokenParsed?.family_name,
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

    // Set up event listeners first, even if Keycloak init fails
    el('login-btn').addEventListener('click', () => {
        console.log('Login button clicked')
        try {
            keycloak.login({
                redirectUri: window.location.href,
            })
        } catch (error) {
            console.error('Login error:', error)
        }
    })

    el('logout-btn').addEventListener('click', () => {
        console.log('Logout button clicked')
        try {
            keycloak.logout({
                redirectUri: window.location.href,
            })
        } catch (error) {
            console.error('Logout error:', error)
        }
    })

    try {
        console.log('Initializing Keycloak...')

        const authenticated = await keycloak.init({
            onLoad: 'check-sso',
            pkceMethod: 'S256',
            checkLoginIframe: false,
            enableLogging: true, // Enable Keycloak logging for debugging
        })

        console.log('Keycloak initialized successfully. Authenticated:', authenticated)
        console.log('Keycloak instance:', keycloak)

        // Show current user state
        showUser()

        // Set up Keycloak event listeners
        keycloak.onAuthSuccess = () => {
            console.log('Authentication successful')
            showUser()
        }

        keycloak.onAuthError = (error) => {
            console.error('Authentication error:', error)
            showUser()
        }

        keycloak.onAuthLogout = () => {
            console.log('User logged out')
            showUser()
        }

        keycloak.onTokenExpired = () => {
            console.log('Token expired, refreshing...')
            keycloak.updateToken(30).then((refreshed) => {
                if (refreshed) {
                    console.log('Token refreshed')
                } else {
                    console.log('Token still valid')
                }
            }).catch((error) => {
                console.error('Failed to refresh token:', error)
                keycloak.login()
            })
        }

    } catch (error) {
        console.error('Failed to initialize Keycloak:', error)
        const container = el('user-info')
        container.innerHTML = `<div style="color: red;">Failed to initialize Keycloak: ${error}</div>`

        // Still show the login button even if init fails
        showUser()
    }
}

init().catch((e) => console.error('Initialization error:', e))

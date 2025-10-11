import { UserManager, WebStorageStateStore, type User } from 'oidc-client-ts'

const oidcConfig = {
  authority: import.meta.env.VITE_AUTHORITY,
  client_id: import.meta.env.VITE_CLIENT_ID,
  redirect_uri: window.location.origin + window.location.pathname,
  response_type: 'code',
  scope: 'openid profile email',
  post_logout_redirect_uri: window.location.origin + window.location.pathname,
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
}

const userManager = new UserManager(oidcConfig)

function el(id: string): HTMLElement {
  const e = document.getElementById(id)
  if (!e) throw new Error(`Element #${id} not found`)
  return e
}

function showUser(user: User | null) {
  const container = el('user-info')
  const loginBtn = el('login-btn') as HTMLButtonElement
  const logoutBtn = el('logout-btn') as HTMLButtonElement

  if (user && !user.expired) {
    container.innerHTML = `<pre>${JSON.stringify(user.profile, null, 2)}</pre>`
    loginBtn.style.display = 'none'
    logoutBtn.style.display = 'inline-block'
  } else {
    container.textContent = 'Not signed in'
    loginBtn.style.display = 'inline-block'
    logoutBtn.style.display = 'none'
  }
}

async function handleCallbackIfNeeded() {
  const params = new URLSearchParams(window.location.search)
  if (params.has('code') && params.has('state')) {
    try {
      console.log('Handling callback with params:', {
        code: params.get('code')?.substring(0, 10) + '...',
        state: params.get('state'),
      })
      await userManager.signinRedirectCallback()
      // remove query params
      window.history.replaceState({}, document.title, window.location.pathname)
      console.log('Callback handled successfully')
    } catch (err) {
      console.error('Error handling signin callback', err)
      // Remove query parameters even on error
      window.history.replaceState({}, document.title, window.location.pathname)
    }
  }
}

async function init() {
  await handleCallbackIfNeeded()

  const user = await userManager.getUser()
  showUser(user)

  el('login-btn').addEventListener('click', async () => {
    await userManager.signinRedirect()
  })

  el('logout-btn').addEventListener('click', async () => {
    await userManager.signoutRedirect()
  })
}

init().catch((e) => console.error(e))

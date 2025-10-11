# Test Client

A test client application for verifying the functionality of vite-plugin-oidc.  
This application implements OpenID Connect authentication using the Authorization Code + PKCE flow.

You can also specify external IdPs (e.g., Keycloak running on localhost:8080) in the .env file to test this client's functionality.

## Getting Started

```bash
npm i
npm run dev

# or

pnpm i
pnpm dev
```

## Authentication Flow

```mermaid
sequenceDiagram
    participant User as User
    participant Client as Test Client<br/>(This App)
    participant AuthServer as Authorization Server<br/>(IdP)

    Note over Client: 1. Generate PKCE Parameters
    Client->>Client: Generate code_verifier
    Client->>Client: Generate code_challenge<br/>(SHA256(code_verifier))

    User->>Client: Click Login Button

    Note over Client, AuthServer: 2. Authorization Request
    Client->>AuthServer: Redirect to authorization endpoint<br/>response_type=code<br/>client_id=test-client<br/>redirect_uri=...<br/>scope=openid profile email<br/>code_challenge=...<br/>code_challenge_method=S256<br/>state=...

    Note over AuthServer: 3. User Authentication
    AuthServer->>User: Display login page
    User->>AuthServer: Enter credentials
    AuthServer->>User: Display consent page (if needed)
    User->>AuthServer: Grant consent

    Note over AuthServer, Client: 4. Authorization Response
    AuthServer->>Client: Redirect to redirect_uri<br/>code=...<br/>state=...

    Note over Client: 5. Authorization Code Validation & Token Exchange
    Client->>Client: Validate state parameter
    Client->>AuthServer: POST to token endpoint<br/>grant_type=authorization_code<br/>code=...<br/>redirect_uri=...<br/>client_id=test-client<br/>code_verifier=...

    Note over AuthServer: 6. PKCE Validation & Token Issuance
    AuthServer->>AuthServer: Verify code_challenge<br/>(SHA256(code_verifier) == code_challenge)
    AuthServer->>Client: Return access token & ID token<br/>access_token=...<br/>id_token=...<br/>token_type=Bearer

    Note over Client: 7. Display User Information
    Client->>Client: Validate & decode ID token
    Client->>User: Display user information

    Note over Client, AuthServer: 8. Logout (Optional)
    User->>Client: Click logout button
    Client->>AuthServer: Redirect to logout endpoint
    AuthServer->>Client: Redirect to post_logout_redirect_uri
```

## Technical Details

### Libraries Used

- `oidc-client-ts`: TypeScript-compatible OpenID Connect client library
- PKCE is automatically handled by the library

### Security Features

- **PKCE (Proof Key for Code Exchange)**: Prevents authorization code interception attacks
- **State Parameter**: Prevents CSRF attacks
- **Nonce**: Prevents ID token replay attacks (automatically handled by library)

### Implementation Highlights

1. Uses `response_type: 'code'` to specify Authorization Code flow
2. Library automatically applies PKCE extension
3. Callback handling exchanges authorization code for tokens
4. State management using session storage and local storage

## Configuration

Configure your OIDC provider settings in the `.env` file:

```bash
# VITE_AUTHORITY is the IdP (Identity Provider) endpoint
# The VITE_AUTHORITY value must match your OIDC provider's issuer URL
VITE_AUTHORITY=http://localhost:5173/realms/myrealm
# For example, to test this client with Keycloak running on localhost:8080 instead of vite-plugin-oidc, use:
#VITE_AUTHORITY=http://localhost:8080/realms/myrealm

# VITE_CLIENT_ID is the OAuth2/OIDC client identifier registered with the IdP
# This value must match a client_id configured in your OIDC provider
VITE_CLIENT_ID=test-client
```

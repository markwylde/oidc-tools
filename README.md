# oidc-tools

A lightweight library for working with OpenID Connect tokens.

## Installation

```bash
npm install oidc-tools
```

## Usage

```javascript
import OidcTools from 'oidc-tools';

// Initialize the library with your OIDC configuration
const issuerURL = process.env.OIDC_ISSUER_URL;
const clientId = process.env.OIDC_CLIENT_ID;
const clientSecret = process.env.OIDC_CLIENT_SECRET;
const redirectUri = process.env.OIDC_REDIRECT_URI;

const { decodeToken, getLoginUrl, exchangeToken, getLogoutUrl } = await OidcTools({
  issuerURL,
  clientId,
  clientSecret,
  redirectUri,
  // Optional: cache options
  cache: true,
  cacheDuration: 300000, // 5 minutes in milliseconds
  // PKCE is enabled by default for security
  usePKCE: true
});

// Decode and verify a JWT token
try {
  const token = 'your-jwt-token';
  const payload = await decodeToken(token);
  console.log(payload);
} catch (error) {
  console.error('Token verification failed:', error.message);
}

// Redirect user to the OAuth login page
const { url, state, nonce, codeVerifier } = getLoginUrl();
console.log(`Redirect user to: ${url}`);

// Generate logout URL
const logoutUrl = getLogoutUrl({
  postLogoutRedirectUri: 'https://your-app/logged-out'
});
console.log(`Logout URL: ${logoutUrl}`);

// In an http app, you could redirect like this:
// res.writeHead(302, { 'Location': url });
// res.end();
//
// Don't forget to store state, nonce, and codeVerifier in your session
// to verify them when the user returns:
// req.session.authState = state;
// req.session.authNonce = nonce;
// req.session.codeVerifier = codeVerifier; // Required for PKCE token exchange
```

## Complete Example: Authentication Flow

Here's a complete example that demonstrates a full authentication flow using a simple HTTP server:

[examples/auth-flow.js](examples/auth-flow.js)

To run this example:

1. Set the environment variables `OIDC_ISSUER_URL` and `OIDC_CLIENT_ID`
2. Make sure your OIDC provider has `http://localhost:8088/callback` configured as an allowed redirect URI
3. Run `npm run example:auth` and visit http://localhost:8088 in your browser

For a more complete example with token exchange, see the `examples/auth-flow.js` file in the repository.

## Environment Variables

The library is designed to work with environment variables for configuration:

- `OIDC_ISSUER_URL`: The URL to your OIDC provider's well-known configuration endpoint
- `OIDC_CLIENT_ID`: Your OAuth client ID
- `OIDC_REDIRECT_URI`: The URI where the OAuth provider should redirect after authentication

You can create a `.env` file in your project root with these variables:

```
OIDC_ISSUER_URL=https://your-oidc-provider/.well-known/openid-configuration
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://your-app/callback
```

## API

### OidcTools(options)

Initialize the OIDC tools library.

**Options:**

- `issuerURL` (required): URL to the OIDC provider's well-known OpenID configuration.
- `clientId` (optional): Your OAuth client ID, required for getLoginUrl.
- `clientSecret` (optional): Your OAuth client secret for confidential clients.
- `redirectUri` (optional): The URI to redirect to after authentication, required for getLoginUrl.
- `scope` (optional): OAuth scopes to request. Default: `'openid profile email'`.
- `cache` (optional): Boolean indicating whether to cache decoded tokens. Default: `true`.
- `cacheDuration` (optional): Duration in milliseconds for how long to cache decoded tokens. Default: `300000` (5 minutes).
- `usePKCE` (optional): Boolean indicating whether to use PKCE for authorization code flow. Default: `true`.

**Returns:**

An object containing the following methods:

### decodeToken(token)

Verifies and decodes a JWT token.

**Parameters:**

- `token` (string): The JWT token to decode.

**Returns:**

A promise that resolves to the decoded token payload.

### getLoginUrl(params)

Generates a URL to redirect users to the OAuth provider's login page, along with secure random state, nonce, and PKCE values.

**Parameters:**

- `params` (optional): Object containing the following optional properties:
  - `state` (string): Optional state value. If not provided, a secure random value will be generated.
  - `nonce` (string): Optional nonce value. If not provided, a secure random value will be generated.
  - `responseType` (string): OAuth response type. Default: `'code'`.

**Returns:**

An object containing:
- `url`: The URL to redirect the user to for authentication
- `state`: The state value (either provided or auto-generated)
- `nonce`: The nonce value (either provided or auto-generated)
- `codeVerifier`: The PKCE code verifier (only if usePKCE is true)
- `codeChallenge`: The PKCE code challenge (only if usePKCE is true)

The state, nonce, and codeVerifier values should be stored in your session and verified when the user returns.

### getLogoutUrl(params)

Generates a URL to log the user out of the OAuth provider's session.

**Parameters:**

- `params` (optional): Object containing the following optional properties:
  - `state` (string): Optional state value. If not provided, a secure random value will be generated.
  - `postLogoutRedirectUri` (string): Optional URI to redirect to after logout. If not provided, the redirectUri from initialization will be used.

**Returns:**

A string URL to redirect the user to for logout.

### exchangeToken(params)

Exchanges an authorization code for tokens, including support for PKCE.

**Parameters:**

- `params` (object): Object containing the following properties:
  - `code` (string, required): The authorization code received from the OAuth provider.
  - `codeVerifier` (string, optional): The PKCE code verifier generated during the login request. Required if PKCE was used.
  - `clientSecret` (string, optional): Client secret for confidential clients. If provided, the client authentication will use Basic auth.

**Returns:**

A promise that resolves to an object containing:
- `access_token`: The OAuth access token
- `id_token`: The OpenID Connect ID token (if requested)
- `refresh_token`: The OAuth refresh token (if requested)
- `token_type`: The token type (usually "Bearer")
- `expires_in`: The token expiration time in seconds

## Running the Example

To run the example using environment variables:

1. Copy `.env.example` to `.env` and update the values with your OIDC provider details
2. Run the example using:

```bash
npm run example
```

Or run the authentication flow example:

```bash
npm run example:auth
```

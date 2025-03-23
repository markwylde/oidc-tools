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

const { decodeToken } = await OidcTools({
  issuerURL,
  // Optional: cache options
  cache: true,
  cacheDuration: 300000 // 5 minutes in milliseconds
});

// Decode and verify a JWT token
try {
  const token = 'your-jwt-token';
  const payload = await decodeToken(token);
  console.log(payload);
} catch (error) {
  console.error('Token verification failed:', error.message);
}
```

## Environment Variables

The library is designed to work with environment variables for configuration:

- `OIDC_ISSUER_URL`: The URL to your OIDC provider's well-known configuration endpoint

You can create a `.env` file in your project root with these variables:

```
OIDC_ISSUER_URL=https://your-oidc-provider/.well-known/openid-configuration
```

## API

### OidcTools(options)

Initialize the OIDC tools library.

**Options:**

- `issuerURL` (required): URL to the OIDC provider's well-known OpenID configuration.
- `cache` (optional): Boolean indicating whether to cache decoded tokens. Default: `true`.
- `cacheDuration` (optional): Duration in milliseconds for how long to cache decoded tokens. Default: `300000` (5 minutes).

**Returns:**

An object containing the following methods:

### decodeToken(token)

Verifies and decodes a JWT token.

**Parameters:**

- `token` (string): The JWT token to decode.

**Returns:**

A promise that resolves to the decoded token payload.

## Running the Example

To run the example using environment variables:

1. Copy `.env.example` to `.env` and update the values with your OIDC provider details
2. Run the example using:

```bash
npm run example
```

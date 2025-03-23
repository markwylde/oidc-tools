import * as jose from 'jose';
import { OidcToolsOptions, OidcToolsInstance, JwtPayload } from './types.js';
import crypto from 'crypto';

// Simple cache implementation
const tokenCache = new Map<string, { payload: JwtPayload; timestamp: number }>();
const DEFAULT_CACHE_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds

// Helper function to generate secure random string
const generateSecureRandomString = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

// Helper function to generate code verifier for PKCE
const generateCodeVerifier = (): string => {
  return crypto.randomBytes(32).toString('base64url');
};

// Helper function to generate code challenge from verifier
const generateCodeChallenge = (verifier: string): string => {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
};

async function OidcTools(options: OidcToolsOptions): Promise<OidcToolsInstance> {
  const {
    issuerURL,
    cache = true,
    cacheDuration = DEFAULT_CACHE_DURATION,
    clientId,
    clientSecret,
    redirectUri,
    scope = 'openid profile email',
    usePKCE = true
  } = options;

  if (!issuerURL) {
    throw new Error('issuerURL is required');
  }

  // Fetch the OpenID configuration
  const configResponse = await fetch(issuerURL);

  if (!configResponse.ok) {
    throw new Error(`Failed to fetch OIDC configuration: ${configResponse.statusText}`);
  }

  const config = await configResponse.json();

  // Create JWKS client with the provided jwks_uri
  const JWKS = jose.createRemoteJWKSet(new URL(config.jwks_uri));

  // The decodeToken function
  const decodeToken = async (token: string): Promise<JwtPayload> => {
    // Check cache first if enabled
    if (cache) {
      const cached = tokenCache.get(token);
      if (cached && Date.now() - cached.timestamp < cacheDuration) {
        return cached.payload;
      }
    }

    try {
      // Verify the token
      const { payload } = await jose.jwtVerify(token, JWKS, {
        issuer: config.issuer,
      });

      // Update cache if enabled
      if (cache) {
        tokenCache.set(token, { payload, timestamp: Date.now() });
      }

      return payload;
    } catch (error) {
      throw new Error(`Token verification failed: ${(error as Error).message}`);
    }
  };

  // Function to build the OAuth login URL
  const getLoginUrl = (params?: { state?: string; nonce?: string; responseType?: string; }) => {
    if (!clientId) {
      throw new Error('clientId is required to generate a login URL');
    }

    if (!redirectUri) {
      throw new Error('redirectUri is required to generate a login URL');
    }

    const authorizationEndpoint = config.authorization_endpoint;
    if (!authorizationEndpoint) {
      throw new Error('Authorization endpoint not found in OIDC configuration');
    }

    // Generate secure random values if not provided
    const state = params?.state ?? generateSecureRandomString();
    const nonce = params?.nonce ?? generateSecureRandomString();

    const searchParams = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      scope,
      response_type: params?.responseType || 'code',
      state,
      nonce
    });

    // If PKCE is enabled, generate code verifier and challenge
    if (usePKCE) {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      searchParams.append('code_challenge', codeChallenge);
      searchParams.append('code_challenge_method', 'S256');

      return {
        url: `${authorizationEndpoint}?${searchParams.toString()}`,
        state,
        nonce,
        codeVerifier,
        codeChallenge
      };
    }

    return {
      url: `${authorizationEndpoint}?${searchParams.toString()}`,
      state,
      nonce
    };
  };

  // Function to exchange authorization code for tokens
  const exchangeToken = async (params: {
    code: string;
    codeVerifier?: string;
    clientSecret?: string;
  }): Promise<{
    access_token: string;
    id_token?: string;
    refresh_token?: string;
    token_type: string;
    expires_in: number;
    [key: string]: any;
  }> => {
    if (!clientId) {
      throw new Error('clientId is required to exchange the authorization code');
    }

    if (!redirectUri) {
      throw new Error('redirectUri is required to exchange the authorization code');
    }

    if (!config.token_endpoint) {
      throw new Error('Token endpoint not found in OIDC configuration');
    }

    const { code, codeVerifier, clientSecret: paramsClientSecret } = params;
    // Use client secret from options or from params
    const secretToUse = clientSecret || paramsClientSecret;

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
    });

    // Add code verifier for PKCE if provided
    if (codeVerifier) {
      body.append('code_verifier', codeVerifier);
    }

    const headers: HeadersInit = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    // Add client authentication if client secret is provided
    if (secretToUse) {
      const auth = Buffer.from(`${clientId}:${secretToUse}`).toString('base64');
      headers['Authorization'] = `Basic ${auth}`;
    }

    const response = await fetch(config.token_endpoint, {
      method: 'POST',
      headers,
      body: body.toString(),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to exchange code for tokens: ${response.statusText}\n${errorText}`);
    }

    return await response.json();
  };

  return {
    decodeToken,
    getLoginUrl,
    exchangeToken,
  };
}

export default OidcTools;
export type { OidcToolsOptions, OidcToolsInstance, JwtPayload };

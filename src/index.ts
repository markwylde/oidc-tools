import * as jose from 'jose';
import { OidcToolsOptions, OidcToolsInstance, JwtPayload } from './types.js';

// Simple cache implementation
const tokenCache = new Map<string, { payload: JwtPayload; timestamp: number }>();
const DEFAULT_CACHE_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds

async function OidcTools(options: OidcToolsOptions): Promise<OidcToolsInstance> {
  const { issuerURL, cache = true, cacheDuration = DEFAULT_CACHE_DURATION } = options;

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

  return {
    decodeToken,
  };
}

export default OidcTools;
export type { OidcToolsOptions, OidcToolsInstance, JwtPayload };
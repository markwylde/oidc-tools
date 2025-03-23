import OidcTools from '../dist/index.js';

// Sample JWT token for demonstration
const token = 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InhxX1FMdjBWRXRRS2R0SkpnVGVjNUdiM3FjaGJwWTdpUEQ2T1NNRG4wYlUifQ';

async function main() {
  try {
    // Get the OIDC issuer URL from environment variables
    const issuerURL = process.env.OIDC_ISSUER_URL;

    if (!issuerURL) {
      console.error('Error: OIDC_ISSUER_URL environment variable is not set.');
      console.error('Please set it in .env file or provide it directly:');
      console.error('  OIDC_ISSUER_URL=https://your-oidc-provider/.well-known/openid-configuration node examples/basic-usage.js');
      process.exit(1);
    }

    console.log(`Connecting to OIDC provider at: ${issuerURL}`);

    // Initialize the OIDC tools
    const { decodeToken } = await OidcTools({
      issuerURL,
      cache: true,
    });

    // Decode the token
    console.log('Decoding token...');
    const payload = await decodeToken(token);

    console.log('Decoded token payload:');
    console.log(JSON.stringify(payload, null, 2));

  } catch (error) {
    console.error('Error:', error.message);

    // Additional error handling based on error type
    if (error.message.includes('Failed to fetch OIDC configuration')) {
      console.error('Check that your OIDC provider is accessible and the URL is correct.');
    } else if (error.message.includes('Token verification failed')) {
      console.error('The token could not be verified. It may be expired or invalid.');
    }
  }
}

main();
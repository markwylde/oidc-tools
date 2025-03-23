import OidcTools from '../dist/index.js';
import http from 'http';
import url from 'url';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// In-memory session storage for demonstration purposes
// In a real app, you would use a proper session management system
const sessions = new Map();

async function main() {
  // Get the OIDC configuration from environment variables
  const issuerURL = process.env.OIDC_ISSUER_URL;
  const clientId = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const redirectUri = process.env.OIDC_REDIRECT_URI || 'http://localhost:8088/callback';

  if (!issuerURL || !clientId) {
    console.error('Error: OIDC_ISSUER_URL and OIDC_CLIENT_ID environment variables are required.');
    process.exit(1);
  }

  console.log(`Connecting to OIDC provider at: ${issuerURL}`);

  // Initialize the OIDC tools with PKCE enabled
  const { decodeToken, getLoginUrl, exchangeToken } = await OidcTools({
    issuerURL,
    clientId,
    clientSecret,
    redirectUri,
    usePKCE: true // Enable PKCE
  });

  // Create an HTTP server
  const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;

    // Home page - check for auth and display user info or login link
    if (path === '/') {
      // Check if the user has a session cookie
      const cookie = req.headers.cookie;
      const sessionId = cookie?.split(';').find(c => c.trim().startsWith('session='))?.split('=')[1];

      if (sessionId && sessions.has(sessionId)) {
        // User is authenticated, display user info
        const userInfo = sessions.get(sessionId);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <h1>Authenticated User</h1>
          <pre>${JSON.stringify(userInfo, null, 2)}</pre>
          <p><a href="/logout">Logout</a></p>
        `);
      } else {
        // User is not authenticated, show login link
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <h1>OIDC Authentication Example</h1>
          <p><a href="/login">Login with OpenID Connect</a></p>
        `);
      }
    }

    // Login route - redirect to OIDC provider
    else if (path === '/login') {
      // Generate login URL with random state, nonce, and PKCE params
      const { url, state, nonce, codeVerifier } = getLoginUrl();

      // Store state, nonce, and code verifier in the session for later verification
      const sessionId = Math.random().toString(36).substring(2);
      sessions.set(sessionId, { state, nonce, codeVerifier });

      // Set session cookie and redirect to OIDC provider
      res.writeHead(302, {
        'Location': url,
        'Set-Cookie': `session=${sessionId}; HttpOnly; Path=/`
      });
      res.end();
    }

    // Callback route - handle OIDC provider response
    else if (path === '/callback') {
      const { code, state, error, error_description } = parsedUrl.query;

      // Handle error response from the OIDC provider
      if (error) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end(`Authentication error: ${error}: ${error_description}`);
        return;
      }

      // Get session from cookie
      const cookie = req.headers.cookie;
      const sessionId = cookie?.split(';').find(c => c.trim().startsWith('session='))?.split('=')[1];

      if (!sessionId || !sessions.has(sessionId)) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Invalid session');
        return;
      }

      const session = sessions.get(sessionId);

      // Verify state parameter to prevent CSRF attacks
      if (state !== session.state) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Invalid state parameter');
        return;
      }

      try {
        // Exchange the code for tokens with PKCE
        const tokens = await exchangeToken({
          code,
          codeVerifier: session.codeVerifier
          // Client secret is automatically used from OidcTools initialization
        });

        const { id_token } = tokens;

        // Use decodeToken to validate and extract user info from the ID token
        const userInfo = await decodeToken(id_token);

        // Store tokens and user info in session
        sessions.set(sessionId, {
          authenticated: true,
          tokens,
          user: userInfo
        });

        // Redirect to home page
        res.writeHead(302, { 'Location': '/' });
        res.end();
      } catch (error) {
        console.error('Token exchange error:', error);
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end(`Authentication failed: ${error.message}`);
      }
    }

    // Logout route
    else if (path === '/logout') {
      // Get session from cookie
      const cookie = req.headers.cookie;
      const sessionId = cookie?.split(';').find(c => c.trim().startsWith('session='))?.split('=')[1];

      if (sessionId) {
        // Clear session
        sessions.delete(sessionId);
      }

      // Clear cookie and redirect to home page
      res.writeHead(302, {
        'Location': '/',
        'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0'
      });
      res.end();
    }

    // Not found
    else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  });

  // Start the server
  const port = process.env.PORT || 8088;
  server.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
    console.log(`Callback URL set to: ${redirectUri}`);
  });
}

main();

export interface OidcToolsOptions {
  issuerURL: string;
  cache?: boolean;
  cacheDuration?: number;
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  scope?: string;
  usePKCE?: boolean;
}

export interface JwtPayload {
  [key: string]: any;
}

export interface OidcToolsInstance {
  decodeToken: (token: string) => Promise<JwtPayload>;
  getLoginUrl: (options?: { state?: string; nonce?: string; responseType?: string; }) => {
    url: string;
    state: string;
    nonce: string;
    codeVerifier?: string;
    codeChallenge?: string;
  };
  exchangeToken: (params: {
    code: string;
    codeVerifier?: string;
    clientSecret?: string;
  }) => Promise<{
    access_token: string;
    id_token?: string;
    refresh_token?: string;
    token_type: string;
    expires_in: number;
    [key: string]: any;
  }>;
}
export interface OidcToolsOptions {
  issuerURL: string;
  cache?: boolean;
  cacheDuration?: number;
}

export interface JwtPayload {
  [key: string]: any;
}

export interface OidcToolsInstance {
  decodeToken: (token: string) => Promise<JwtPayload>;
}
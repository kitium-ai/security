declare module '@kitium-ai/auth' {
  export interface OIDCAdapterOptions {
    issuer: string;
    clientId: string;
    clientSecret?: string;
    redirectUri?: string;
    scopes?: string[];
  }

  export interface SAMLAdapterOptions {
    entryPoint: string;
    callbackUrl: string;
    issuer: string;
  }

  export interface SCIMSyncEvent {
    type: string;
    payload: Record<string, any>;
  }

  export class AuthClient {
    constructor(options?: Record<string, any>);
    createOIDCMiddleware(options: OIDCAdapterOptions): any;
    createSAMLMiddleware(options: SAMLAdapterOptions): any;
    handleSCIM(event: SCIMSyncEvent): Promise<void>;
    validateSession(token: string): Promise<any>;
  }
}

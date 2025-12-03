import { Request, Response, NextFunction } from 'express';
import { AuthClient, OIDCAdapterOptions, SAMLAdapterOptions } from '@kitium-ai/auth';
import { IdentityProviderConfig, ScimEvent, SecurityContext } from '../types';
import { auditLogService } from './auditLog';
import { logger } from '../utils/logger';

export class IdentityFederationService {
  private authClient: AuthClient;

  constructor(providers: IdentityProviderConfig[] = []) {
    this.authClient = new AuthClient({ providers });
  }

  public updateProviders(providers: IdentityProviderConfig[]): void {
    // Update auth client with new providers
    this.authClient = new AuthClient({ providers });
  }

  public setProviders(providers: IdentityProviderConfig[]): void {
    this.updateProviders(providers);
  }

  public createOidcMiddleware(provider: IdentityProviderConfig) {
    const options: OIDCAdapterOptions = {
      issuer: provider.issuer,
      clientId: provider.clientId || '',
      clientSecret: provider.clientSecret,
      scopes: provider.scopes || ['openid', 'profile', 'email'],
      redirectUri: `${provider.issuer}/callback`,
    };

    return this.authClient.createOIDCMiddleware(options);
  }

  public createSamlMiddleware(provider: IdentityProviderConfig) {
    const options: SAMLAdapterOptions = {
      entryPoint: provider.samlEntryPoint || provider.issuer,
      callbackUrl: provider.samlCallbackUrl || `${provider.issuer}/saml/callback`,
      issuer: provider.issuer,
    };

    return this.authClient.createSAMLMiddleware(options);
  }

  public handleScimSync(event: ScimEvent): Promise<void> {
    return this.authClient.handleSCIM({ type: event.type, payload: event.payload });
  }

  public requireConsentScopes(requiredScopes: string[]) {
    return (req: Request, res: Response, next: NextFunction) => {
      const context = req.securityContext as SecurityContext | undefined;
      const consentScopes = context?.consentScopes || [];
      const missing = requiredScopes.filter((scope) => !consentScopes.includes(scope));

      if (missing.length) {
        logger.warn('Consent scopes missing', {
          requiredScopes: missing,
          requestId: context?.requestId,
        });
        return res.status(403).json({
          error: 'Consent scopes missing',
          requiredScopes: missing,
          requestId: context?.requestId,
        });
      }

      return next();
    };
  }

  public requireStepUp(requiredLevel: 'medium' | 'high') {
    return (req: Request, res: Response, next: NextFunction) => {
      const context = req.securityContext as SecurityContext | undefined;
      const assurance = context?.assuranceLevel || 'low';
      const allowed =
        assurance === 'high' || (assurance === 'medium' && requiredLevel === 'medium');

      if (!allowed) {
        auditLogService.logSecurityViolation(
          context?.organizationId || 'unknown',
          'step_up_required',
          {
            requestId: context?.requestId,
            assurance,
            requiredLevel,
          }
        );

        return res.status(401).json({
          error: 'Step-up authentication required',
          requiredLevel,
          requestId: context?.requestId,
        });
      }

      return next();
    };
  }
}

export const identityFederationService = new IdentityFederationService();

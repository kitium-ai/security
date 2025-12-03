import { Application, RequestHandler } from 'express';
import { configManager } from '../config';
import { securityMiddlewareFactory } from './factory';
import { observabilityService } from '../services/observability';
import { networkProtectionService } from '../services/networkProtection';
import { policyEngineService } from '../services/policyEngine';
import { identityFederationService } from '../services/identityFederation';
import { dataGovernanceService } from '../services/dataGovernance';
import { secretProviderService } from '../services/secretProvider';
import { keyManagementService } from '../services/keyManagement';
import { SecuritySuiteOptions } from '../types';

export function applySecureDefaults(app: Application, options: SecuritySuiteOptions = {}) {
  if (options.identityProviders) {
    identityFederationService.setProviders(options.identityProviders);
  }

  if (options.policyBackend) {
    policyEngineService.setBackend(options.policyBackend);
  }

  const config = configManager.getConfig();

  app.use(securityMiddlewareFactory.createContextMiddleware());
  app.use(networkProtectionService.bodySizeGuard());
  app.use(observabilityService.tracingMiddleware());
  app.use(observabilityService.metricsMiddleware());
  app.use(securityMiddlewareFactory.createRequestIdMiddleware());
  app.use(networkProtectionService.enforceIpPolicy());
  app.use(networkProtectionService.requireMutualTLS());
  app.use(securityMiddlewareFactory.createHelmetMiddleware());
  app.use(securityMiddlewareFactory.createCorsMiddleware());
  app.use(securityMiddlewareFactory.createRateLimitMiddleware());
  app.use(securityMiddlewareFactory.createAuditLoggingMiddleware());
  app.use(networkProtectionService.signResponse());

  const readinessPath = config.readinessPath || '/ready';
  const livenessPath = config.livenessPath || '/live';
  app.get(readinessPath, observabilityService.readinessMiddleware());
  app.get(livenessPath, observabilityService.livenessMiddleware());

  return app;
}

export function createSecuritySuite(options: SecuritySuiteOptions & { app?: Application } = {}) {
  const apply = (app?: Application) => {
    if (app) {
      applySecureDefaults(app, options);
    }
  };

  apply(options.app);
  return {
    middleware: securityMiddlewareFactory,
    observability: observabilityService,
    identity: identityFederationService,
    policy: policyEngineService,
    network: networkProtectionService,
    data: dataGovernanceService,
    secrets: secretProviderService,
    keys: keyManagementService,
    requirePolicy: (action: string, resource: string): RequestHandler =>
      policyEngineService.middleware(action, resource),
    requireStepUp: (level: 'medium' | 'high'): RequestHandler =>
      identityFederationService.requireStepUp(level),
    requireConsent: (scopes: string[]): RequestHandler =>
      identityFederationService.requireConsentScopes(scopes),
    apply: applySecureDefaults,
  };
}

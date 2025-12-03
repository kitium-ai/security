import { Request, Response, NextFunction } from 'express';
import { PolicyDecision, PolicyDecisionContext } from '../types';
import { logger } from '../utils/logger';

export class PolicyEngineService {
  private policyCache: Map<string, PolicyDecision> = new Map();
  private bundleStore: Map<string, Record<string, any>> = new Map();

  public setBackend(_backend: 'opa' | 'cedar' | 'local') {
    // Backend configuration would be used here in a real implementation
    logger.info('Policy backend set', { backend: _backend });
  }

  public loadBundle(tenant: string, bundle: Record<string, any>): void {
    this.bundleStore.set(tenant, bundle);
  }

  public evaluate(context: PolicyDecisionContext): PolicyDecision {
    const cacheKey = `${context.tenant}:${context.subject}:${context.action}:${context.resource}`;
    const cached = this.policyCache.get(cacheKey);
    if (cached) {
      return { ...cached, cacheHit: true };
    }

    const bundle = this.bundleStore.get(context.tenant) || {};
    const allow = this.runLocalEvaluation(context, bundle);
    const decision: PolicyDecision = {
      allow,
      reason: allow ? 'policy.allow' : 'policy.deny',
      obligations: bundle.obligations || {},
    };

    this.policyCache.set(cacheKey, decision);
    return decision;
  }

  public middleware(
    requiredAction: string,
    resource: string,
    tenantResolver?: (req: Request) => string
  ) {
    return (req: Request, res: Response, next: NextFunction) => {
      const tenant = tenantResolver
        ? tenantResolver(req)
        : req.securityContext?.organizationId || 'default';
      const context: PolicyDecisionContext = {
        subject: req.tokenPayload?.userId || 'anonymous',
        action: requiredAction,
        resource,
        tenant,
        attributes: {
          role: req.tokenPayload?.role,
          permissions: req.tokenPayload?.permissions,
          method: req.method,
        },
      };

      const decision = this.evaluate(context);

      if (!decision.allow) {
        logger.warn('Policy denied request', { context, reason: decision.reason });
        return res.status(403).json({ error: 'Policy denied request', reason: decision.reason });
      }

      return next();
    };
  }

  private runLocalEvaluation(context: PolicyDecisionContext, bundle: Record<string, any>): boolean {
    const allowList = bundle.allow || [];
    const denyList = bundle.deny || [];

    if (
      denyList.some(
        (rule: any) => rule.action === context.action && rule.resource === context.resource
      )
    ) {
      return false;
    }

    if (allowList.length === 0) {
      return true;
    }

    return allowList.some((rule: any) => {
      const actionMatch = rule.action === context.action || rule.action === '*';
      const resourceMatch = rule.resource === context.resource || rule.resource === '*';
      const roleMatch = !rule.role || rule.role === context.attributes?.role;
      return actionMatch && resourceMatch && roleMatch;
    });
  }
}

export const policyEngineService = new PolicyEngineService();

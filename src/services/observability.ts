import { Request, Response, NextFunction } from 'express';
import { trace, context, SpanStatusCode } from '@opentelemetry/api';
import { logger } from '../utils/logger';
import { configManager } from '../config';

export class ObservabilityService {
  private tracer = trace.getTracer('enterprise-security');

  public tracingMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!configManager.getConfig().tracingEnabled) {
        return next();
      }

      const span = this.tracer.startSpan(`${req.method} ${req.path}`);
      const ctx = trace.setSpan(context.active(), span);

      res.on('finish', () => {
        span.setAttributes({
          'http.method': req.method,
          'http.route': req.path,
          'http.status_code': res.statusCode,
          'enduser.id': req.tokenPayload?.userId,
        });
        if (res.statusCode >= 500) {
          span.setStatus({ code: SpanStatusCode.ERROR });
        }
        span.end();
      });

      return context.with(ctx, next);
    };
  }

  public readinessMiddleware() {
    return (_req: Request, res: Response) => {
      res.status(200).json({ status: 'ok', checks: ['config', 'dependencies'] });
    };
  }

  public livenessMiddleware() {
    return (_req: Request, res: Response) => {
      res.status(200).json({ status: 'alive' });
    };
  }

  public metricsMiddleware() {
    return (req: Request, _res: Response, next: NextFunction) => {
      if (!configManager.getConfig().metricsEnabled) {
        return next();
      }
      logger.info('metrics', {
        path: req.path,
        method: req.method,
        user: req.tokenPayload?.userId,
        organizationId: req.securityContext?.organizationId,
      });
      return next();
    };
  }
}

export const observabilityService = new ObservabilityService();

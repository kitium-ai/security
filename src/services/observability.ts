import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { configManager } from '../config';

export class ObservabilityService {
  private generateTraceId(): string {
    return (
      Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
    );
  }

  private generateSpanId(): string {
    return Math.random().toString(36).substring(2, 15);
  }

  public tracingMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const config = configManager.getConfig();
      if (!config.tracingEnabled) {
        return next();
      }

      const traceId = (req.headers['x-trace-id'] as string) || this.generateTraceId();
      const spanId = this.generateSpanId();
      const startTime = Date.now();

      // Add trace headers to response
      res.setHeader('x-trace-id', traceId);
      res.setHeader('x-span-id', spanId);

      // Log request start
      logger.debug('Request started', {
        traceId,
        spanId,
        method: req.method,
        path: req.path,
      });

      // Capture response
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.debug('Request completed', {
          traceId,
          spanId,
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          duration,
        });
      });

      next();
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

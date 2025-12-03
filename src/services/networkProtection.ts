import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { configManager } from '../config';
import { auditLogService } from './auditLog';
import { logger } from '../utils/logger';

export class NetworkProtectionService {
  public requireMutualTLS() {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!configManager.getConfig().mTLSRequired) {
        return next();
      }

      const authorized = (req.socket as any).authorized;
      if (!authorized) {
        auditLogService.logSecurityViolation(
          req.securityContext?.organizationId || 'unknown',
          'mtls_failed',
          {
            requestId: req.securityContext?.requestId,
          }
        );
        return res.status(401).json({ error: 'mTLS client certificate required' });
      }

      return next();
    };
  }

  public enforceIpPolicy() {
    return (req: Request, res: Response, next: NextFunction) => {
      const allowed = configManager.getConfig().allowedIpCidrs || [];
      const denied = configManager.getConfig().deniedIpCidrs || [];
      const clientIp = req.ip || '';

      if (denied.includes(clientIp)) {
        return res.status(403).json({ error: 'IP blocked' });
      }

      if (allowed.length && !allowed.includes(clientIp)) {
        return res.status(403).json({ error: 'IP not allowlisted' });
      }

      return next();
    };
  }

  public bodySizeGuard() {
    return (req: Request, _res: Response, next: NextFunction) => {
      const chunks: Buffer[] = [];
      const limit = configManager.getConfig().maxRequestBodyBytes || 0;
      let size = 0;

      req.on('data', (chunk) => {
        size += chunk.length;
        chunks.push(chunk);
        if (limit && size > limit) {
          req.socket.destroy();
          logger.warn('Request body rejected due to size limit', { limit });
        }
      });

      req.on('end', () => {
        if (size <= limit || !limit) {
          (req as any).rawBody = Buffer.concat(chunks);
        }
      });

      next();
    };
  }

  public signResponse() {
    return (_req: Request, res: Response, next: NextFunction) => {
      const key = configManager.getConfig().responseSigningKey;
      if (!key) {
        return next();
      }

      const originalJson = res.json.bind(res);
      res.json = (body: any) => {
        const payload = JSON.stringify(body);
        const signature = crypto.createHmac('sha256', key).update(payload).digest('base64');
        res.setHeader('X-Response-Signature', signature);
        return originalJson({ ...body, signature });
      };

      next();
    };
  }

  public fileScanMiddleware(scanner: (buffer: Buffer) => Promise<boolean>) {
    return async (req: Request, res: Response, next: NextFunction) => {
      const rawBody = (req as any).rawBody as Buffer | undefined;
      if (!rawBody) {
        return next();
      }

      const clean = await scanner(rawBody);
      if (!clean) {
        auditLogService.logSecurityViolation(
          req.securityContext?.organizationId || 'unknown',
          'file_scan_failed',
          {
            requestId: req.securityContext?.requestId,
          }
        );
        return res.status(400).json({ error: 'Malicious file detected' });
      }

      return next();
    };
  }
}

export const networkProtectionService = new NetworkProtectionService();

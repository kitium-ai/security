/**
 * Security Middleware Factory
 * Provides a factory pattern for creating and composing security middleware
 */

import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import Joi from 'joi';

import { configManager } from '../config';
import { authenticationService } from '../services/authentication';
import { authorizationService } from '../services/authorization';
import { auditLogService } from '../services/auditLog';
import { csrfProtectionService } from '../services/csrf';
import { encryptionService } from '../utils/encryption';
import { logger } from '../utils/logger';
import { SecurityContext, AuthTokenPayload, ValidationSchema } from '../types';

/**
 * Extend Express Request with security context
 */
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      securityContext?: SecurityContext;
      tokenPayload?: AuthTokenPayload;
    }
  }
}

export class SecurityMiddlewareFactory {
  private config = configManager.getConfig();

  /**
   * Create request ID middleware
   */
  public createRequestIdMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      req.securityContext = {
        requestId: auditLogService.generateRequestId(),
        organizationId: (req.headers['x-organization-id'] as string) || 'default',
        permissions: [],
        timestamp: Date.now(),
        ipAddress: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
      };

      res.setHeader('X-Request-ID', req.securityContext.requestId);
      next();
    };
  }

  /**
   * Create helmet security headers middleware
   */
  public createHelmetMiddleware() {
    return helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      frameguard: { action: 'deny' },
      noSniff: true,
      xssFilter: true,
    });
  }

  /**
   * Create CORS middleware
   */
  public createCorsMiddleware() {
    return cors({
      origin: this.config.corsOrigins,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Organization-ID', 'X-Request-ID'],
      maxAge: 86400,
    });
  }

  /**
   * Create rate limiting middleware
   */
  public createRateLimitMiddleware() {
    if (!this.config.enableRateLimiting) {
      return (_req: Request, _res: Response, next: NextFunction) => next();
    }

    return rateLimit({
      windowMs: this.config.rateLimitWindowMs,
      max: this.config.rateLimitMaxRequests,
      keyGenerator: (req: Request) => {
        return (req.securityContext?.organizationId || 'default') + ':' + (req.ip || 'unknown');
      },
      handler: (req: Request, res: Response) => {
        const context = req.securityContext;
        if (context) {
          auditLogService.logSecurityViolation(context.organizationId, 'rate_limit_exceeded', {
            ipAddress: context.ipAddress,
            requestId: context.requestId,
          });
        }

        res.status(429).json({
          error: 'Too many requests, please try again later',
          requestId: context?.requestId,
        });
      },
    });
  }

  /**
   * Create authentication middleware
   */
  public createAuthenticationMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const context = req.securityContext;
      if (!context) {
        return res.status(500).json({ error: 'Security context not initialized' });
      }

      // Skip auth for public endpoints
      const publicPaths = ['/health', '/status', '/docs'];
      if (publicPaths.includes(req.path)) {
        return next();
      }

      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        auditLogService.logAuthenticationAttempt(
          'unknown',
          context.organizationId,
          false,
          context.ipAddress
        );

        return res.status(401).json({
          error: 'Missing or invalid authorization header',
          requestId: context.requestId,
        });
      }

      const token = authHeader.substring(7);

      if (!authenticationService.validateTokenStructure(token)) {
        return res.status(401).json({
          error: 'Invalid token format',
          requestId: context.requestId,
        });
      }

      const payload = authenticationService.verifyToken(token);
      if (!payload) {
        auditLogService.logAuthenticationAttempt(
          'unknown',
          context.organizationId,
          false,
          context.ipAddress
        );

        return res.status(401).json({
          error: 'Invalid or expired token',
          requestId: context.requestId,
        });
      }

      // Verify organization match
      if (payload.organizationId !== context.organizationId) {
        auditLogService.logSecurityViolation(context.organizationId, 'organization_mismatch', {
          tokenOrgId: payload.organizationId,
          headerOrgId: context.organizationId,
        });

        return res.status(403).json({
          error: 'Organization mismatch',
          requestId: context.requestId,
        });
      }

      req.tokenPayload = payload;
      context.userId = payload.userId;
      context.role = payload.role;
      context.permissions = payload.permissions;

      auditLogService.logAuthenticationAttempt(
        payload.userId,
        context.organizationId,
        true,
        context.ipAddress
      );

      next();
    };
  }

  /**
   * Create authorization middleware
   */
  public createAuthorizationMiddleware(requiredPermissions: string[]) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const context = req.securityContext;
      if (!context || !req.tokenPayload) {
        res.status(500).json({ error: 'Security context not initialized' });
        return;
      }

      if (!authorizationService.hasAllPermissions(req.tokenPayload, requiredPermissions)) {
        auditLogService.logAuthorizationFailure(
          req.tokenPayload.userId,
          context.organizationId,
          requiredPermissions.join(', ')
        );

        res.status(403).json({
          error: 'Insufficient permissions',
          requiredPermissions,
          requestId: context.requestId,
        });
        return;
      }

      next();
    };
  }

  /**
   * Create request validation middleware
   */
  public createValidationMiddleware(schema: ValidationSchema) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const context = req.securityContext;
      if (!context) {
        res.status(500).json({ error: 'Security context not initialized' });
        return;
      }

      // Build Joi schema from validation schema
      const joiSchema = this.buildJoiSchema(schema);

      const { error, value } = joiSchema.validate(req.body);

      if (error) {
        logger.warn('Request validation failed', {
          requestId: context.requestId,
          error: error.details,
        });

        res.status(400).json({
          error: 'Validation failed',
          details: error.details,
          requestId: context.requestId,
        });
        return;
      }

      req.body = value;
      next();
    };
  }

  /**
   * Create audit logging middleware
   */
  public createAuditLoggingMiddleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
      const context = req.securityContext;
      if (!context) {
        next();
        return;
      }

      res.on('finish', () => {
        auditLogService.logRequest({
          id: auditLogService.generateRequestId(),
          requestId: context.requestId,
          userId: context.userId,
          organizationId: context.organizationId,
          action: `${req.method} ${req.path}`,
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          ipAddress: context.ipAddress,
          timestamp: Date.now(),
        });
      });

      next();
    };
  }

  /**
   * Create encryption middleware for sensitive responses
   */
  public createEncryptionMiddleware(sensitiveFields: string[] = []) {
    return (_req: Request, res: Response, next: NextFunction): void => {
      if (!this.config.enableEncryption || sensitiveFields.length === 0) {
        next();
        return;
      }

      const originalJson = res.json.bind(res);

      res.json = function (data: any) {
        try {
          const encrypted = encryptionService.encrypt(JSON.stringify(data));
          return originalJson({
            encrypted: encrypted.encrypted,
            iv: encrypted.iv,
            authTag: encrypted.authTag,
          });
        } catch (error) {
          logger.error('Encryption failed', { error: (error as Error).message });
          return originalJson(data);
        }
      };

      next();
    };
  }

  /**
   * Create request context middleware
   */
  public createContextMiddleware() {
    return (req: Request, _res: Response, next: NextFunction) => {
      if (!req.securityContext) {
        req.securityContext = {
          requestId: auditLogService.generateRequestId(),
          organizationId: (req.headers['x-organization-id'] as string) || 'default',
          permissions: [],
          timestamp: Date.now(),
          ipAddress: req.ip || 'unknown',
          userAgent: req.headers['user-agent'] || 'unknown',
        };
      }
      next();
    };
  }

  /**
   * Create CSRF protection middleware (double-submit cookie pattern)
   */
  public createCsrfMiddleware(
    options: {
      ignoreMethods?: string[];
      cookieName?: string;
      headerName?: string;
    } = {}
  ) {
    const ignoreMethods = options.ignoreMethods || ['GET', 'HEAD', 'OPTIONS'];
    const cookieName = options.cookieName || 'XSRF-TOKEN';
    const headerName = options.headerName || 'X-XSRF-TOKEN';

    return (req: Request, res: Response, next: NextFunction) => {
      const context = req.securityContext;

      // Generate token for all requests (stored in cookie)
      if (!req.cookies || !req.cookies[cookieName]) {
        const csrfToken = csrfProtectionService.generateToken(context?.userId);

        res.cookie(cookieName, csrfToken.token, {
          httpOnly: false, // Must be readable by JavaScript to send in header
          secure: this.config.environment === 'production',
          sameSite: 'strict',
          maxAge: 3600000, // 1 hour
        });

        // Also send in response header for SPA apps
        res.setHeader(headerName, csrfToken.token);
      }

      // Skip validation for safe methods
      if (ignoreMethods.includes(req.method)) {
        return next();
      }

      // Validate CSRF token for state-changing requests
      const cookieToken = req.cookies?.[cookieName];
      const headerToken = req.headers[headerName.toLowerCase()] as string;

      if (!cookieToken || !headerToken) {
        if (context) {
          auditLogService.logSecurityViolation(context.organizationId, 'csrf_token_missing', {
            requestId: context.requestId,
          });
        }

        return res.status(403).json({
          error: 'CSRF token missing',
          requestId: context?.requestId,
        });
      }

      // Verify double-submit pattern
      if (!csrfProtectionService.verifyDoubleSubmit(cookieToken, headerToken)) {
        if (context) {
          auditLogService.logSecurityViolation(context.organizationId, 'csrf_token_invalid', {
            requestId: context.requestId,
          });
        }

        return res.status(403).json({
          error: 'CSRF token validation failed',
          requestId: context?.requestId,
        });
      }

      // Validate token exists in store
      if (!csrfProtectionService.validateToken(cookieToken, context?.userId)) {
        if (context) {
          auditLogService.logSecurityViolation(context.organizationId, 'csrf_token_expired', {
            requestId: context.requestId,
          });
        }

        return res.status(403).json({
          error: 'CSRF token expired or invalid',
          requestId: context?.requestId,
        });
      }

      next();
    };
  }

  /**
   * Create input sanitization middleware
   */
  public createSanitizationMiddleware(
    options: {
      sanitizeBody?: boolean;
      sanitizeQuery?: boolean;
      sanitizeParams?: boolean;
      maxLength?: number;
      detectMalicious?: boolean;
    } = {}
  ) {
    const {
      sanitizeBody = true,
      sanitizeQuery = true,
      sanitizeParams = true,
      maxLength = 10000,
    } = options;

    return (req: Request, res: Response, next: NextFunction) => {
      const context = req.securityContext;

      try {
        // Basic sanitization - escape HTML special characters
        const basicSanitize = (str: string): string => {
          return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .substring(0, maxLength);
        };

        // Sanitize request body
        if (sanitizeBody && req.body) {
          if (typeof req.body === 'string') {
            req.body = basicSanitize(req.body);
          } else if (typeof req.body === 'object') {
            // Recursively sanitize object
            const sanitizeObject = (obj: any): any => {
              if (typeof obj === 'string') {
                return basicSanitize(obj);
              } else if (Array.isArray(obj)) {
                return obj.map(sanitizeObject);
              } else if (obj && typeof obj === 'object') {
                const result: any = {};
                for (const [key, value] of Object.entries(obj)) {
                  result[key] = sanitizeObject(value);
                }
                return result;
              }
              return obj;
            };
            req.body = sanitizeObject(req.body);
          }
        }

        // Sanitize query parameters
        if (sanitizeQuery && req.query) {
          const sanitizedQuery: Record<string, any> = {};
          for (const [key, value] of Object.entries(req.query)) {
            if (typeof value === 'string') {
              sanitizedQuery[key] = basicSanitize(value);
            } else {
              sanitizedQuery[key] = value;
            }
          }
          req.query = sanitizedQuery;
        }

        // Sanitize route parameters
        if (sanitizeParams && req.params) {
          const sanitizedParams: Record<string, any> = {};
          for (const [key, value] of Object.entries(req.params)) {
            if (typeof value === 'string') {
              sanitizedParams[key] = basicSanitize(value);
            } else {
              sanitizedParams[key] = value;
            }
          }
          req.params = sanitizedParams;
        }

        next();
      } catch (error) {
        logger.error('Sanitization middleware error', {
          error: (error as Error).message,
          requestId: context?.requestId,
        });

        res.status(500).json({
          error: 'Input sanitization failed',
          requestId: context?.requestId,
        });
      }
    };
  }

  /**
   * Create secure cookie middleware
   */
  public createSecureCookieMiddleware() {
    return (_req: Request, res: Response, next: NextFunction): void => {
      // Override res.cookie to enforce secure defaults
      const originalCookie = res.cookie.bind(res);

      res.cookie = function (name: string, value: any, options: any = {}) {
        const secureOptions = {
          httpOnly: true,
          secure: configManager.getConfig().environment === 'production',
          sameSite: 'strict' as const,
          ...options,
        };

        return originalCookie(name, value, secureOptions);
      };

      next();
    };
  }

  /**
   * Helper method to build Joi schema
   */
  private buildJoiSchema(schema: ValidationSchema): Joi.ObjectSchema {
    const joiObject: Record<string, any> = {};

    for (const [key, rules] of Object.entries(schema)) {
      let joiField: Joi.Schema = Joi.any();

      if (rules.type === 'string') {
        joiField = Joi.string();
        if (rules.minLength) {
          joiField = (joiField as Joi.StringSchema).min(rules.minLength);
        }
        if (rules.maxLength) {
          joiField = (joiField as Joi.StringSchema).max(rules.maxLength);
        }
        if (rules.pattern) {
          joiField = (joiField as Joi.StringSchema).pattern(new RegExp(rules.pattern));
        }
      } else if (rules.type === 'number') {
        joiField = Joi.number();
      } else if (rules.type === 'boolean') {
        joiField = Joi.boolean();
      } else if (rules.type === 'email') {
        joiField = Joi.string().email();
      }

      if (rules.enum) {
        joiField = joiField.valid(...rules.enum);
      }

      if (rules.required) {
        joiField = joiField.required();
      } else {
        joiField = joiField.optional();
      }

      joiObject[key] = joiField;
    }

    return Joi.object(joiObject);
  }
}

export const securityMiddlewareFactory = new SecurityMiddlewareFactory();

/**
 * Enterprise Security Middleware - Main Entry Point
 */

// Configuration
export { ConfigManager, configManager } from './config';

// Services
export { AuthenticationService, authenticationService } from './services/authentication';
export { AuthorizationService, authorizationService } from './services/authorization';
export { AuditLogService, auditLogService } from './services/auditLog';

// Utils
export { EncryptionService, encryptionService } from './utils/encryption';
export { logger } from './utils/logger';

// Middleware
export { SecurityMiddlewareFactory, securityMiddlewareFactory } from './middleware/factory';

// Types
export type {
  SecurityContext,
  SecurityConfig,
  AuthTokenPayload,
  AuditLog,
  RateLimitConfig,
  EncryptionConfig,
  AuthorizationPolicy,
  SecurityEvent,
  ValidationSchema,
} from './types';

/**
 * Initialize security middleware with default configuration
 */
export async function initializeSecurityMiddleware() {
  const config = (await import('./config')).configManager.getConfig();
  const validation = (await import('./config')).configManager.validateConfig();

  if (!validation.valid) {
    throw new Error(`Configuration validation failed:\n${validation.errors.join('\n')}`);
  }

  const logger = (await import('./utils/logger')).logger;

  logger.info('Security middleware initialized', {
    environment: config.environment,
    enableEncryption: config.enableEncryption,
    enableAuditLogging: config.enableAuditLogging,
    enableRateLimiting: config.enableRateLimiting,
  });

  return {
    factory: (await import('./middleware/factory')).securityMiddlewareFactory,
    authenticationService: (await import('./services/authentication')).authenticationService,
    authorizationService: (await import('./services/authorization')).authorizationService,
    auditLogService: (await import('./services/auditLog')).auditLogService,
    encryptionService: (await import('./utils/encryption')).encryptionService,
    config,
  };
}

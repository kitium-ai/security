/**
 * Configuration Management System
 */

import { SecurityConfig } from '../types';

export class ConfigManager {
  private static instance: ConfigManager;
  private config: SecurityConfig;

  private constructor() {
    this.config = this.loadConfig();
  }

  static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  private loadConfig(): SecurityConfig {
    const env = process.env.NODE_ENV || 'development';

    return {
      environment: (env as any) || 'development',
      enableEncryption: process.env.ENABLE_ENCRYPTION !== 'false',
      enableAuditLogging: process.env.ENABLE_AUDIT_LOGGING !== 'false',
      enableRateLimiting: process.env.ENABLE_RATE_LIMITING !== 'false',
      jwtSecret: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      jwtExpiration: process.env.JWT_EXPIRATION || '24h',
      encryptionKey: process.env.ENCRYPTION_KEY || 'your-encryption-key-32-bytes-long!',
      corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(','),
      rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
      rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
      auditLogPath: process.env.AUDIT_LOG_PATH || './logs/audit.log',
      logLevel: (process.env.LOG_LEVEL as any) || 'info',
      tracingEnabled: process.env.TRACING_ENABLED !== 'false',
      metricsEnabled: process.env.METRICS_ENABLED !== 'false',
      readinessPath: process.env.READINESS_PATH || '/ready',
      livenessPath: process.env.LIVENESS_PATH || '/live',
      featureFlags: {
        strictCors: process.env.FEATURE_FLAG_STRICT_CORS !== 'false',
        burstRateLimit: process.env.FEATURE_FLAG_BURST_RATE_LIMIT === 'true',
      },
      jwksRotationIntervalMinutes: parseInt(process.env.JWKS_ROTATION_INTERVAL || '60', 10),
      tokenRevocationTtlMinutes: parseInt(process.env.TOKEN_REVOCATION_TTL || '60', 10),
      kmsProvider: (process.env.KMS_PROVIDER as any) || 'local',
      kmsKeyId: process.env.KMS_KEY_ID || 'local-kms-key',
      secretManager: (process.env.SECRET_MANAGER as any) || 'local',
      secretsNamespace: process.env.SECRETS_NAMESPACE || 'security-middleware',
      policyBackend: (process.env.POLICY_BACKEND as any) || 'local',
      policyBundlePath: process.env.POLICY_BUNDLE_PATH,
      mTLSRequired: process.env.MTLS_REQUIRED === 'true',
      allowedIpCidrs: (process.env.ALLOWED_IP_CIDRS || '').split(',').filter(Boolean),
      deniedIpCidrs: (process.env.DENIED_IP_CIDRS || '').split(',').filter(Boolean),
      maxRequestBodyBytes: parseInt(process.env.MAX_REQUEST_BODY_BYTES || '1048576', 10),
      responseSigningKey: process.env.RESPONSE_SIGNING_KEY || 'local-response-signing-key',
      piiFields: (process.env.PII_FIELDS || '').split(',').filter(Boolean),
      auditRetentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS || '30', 10),
    };
  }

  public getConfig(): Readonly<SecurityConfig> {
    return Object.freeze({ ...this.config });
  }

  public updateConfig(partialConfig: Partial<SecurityConfig>): void {
    this.config = { ...this.config, ...partialConfig };
  }

  public getEnvironment(): string {
    return this.config.environment;
  }

  public isProduction(): boolean {
    return this.config.environment === 'production';
  }

  public isDevelopment(): boolean {
    return this.config.environment === 'development';
  }

  public validateConfig(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!this.config.jwtSecret || this.config.jwtSecret.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters long');
    }

    if (!this.config.encryptionKey || this.config.encryptionKey.length < 32) {
      errors.push('ENCRYPTION_KEY must be at least 32 characters long');
    }

    if (this.config.corsOrigins.length === 0) {
      errors.push('At least one CORS origin must be configured');
    }

    if (this.config.rateLimitWindowMs <= 0) {
      errors.push('Rate limit window must be positive');
    }

    if (this.config.rateLimitMaxRequests <= 0) {
      errors.push('Rate limit max requests must be positive');
    }

    if (!this.config.responseSigningKey) {
      errors.push('RESPONSE_SIGNING_KEY is required for response signing');
    }

    if (!this.config.kmsKeyId) {
      errors.push('KMS_KEY_ID must be defined to support envelope encryption');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

export const configManager = ConfigManager.getInstance();

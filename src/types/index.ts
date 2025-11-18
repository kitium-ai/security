/**
 * Enterprise Security Middleware - Type Definitions
 */

export interface SecurityContext {
  requestId: string;
  userId?: string;
  organizationId: string;
  role?: string;
  permissions: string[];
  timestamp: number;
  ipAddress: string;
  userAgent: string;
}

export interface SecurityConfig {
  environment: 'development' | 'staging' | 'production';
  enableEncryption: boolean;
  enableAuditLogging: boolean;
  enableRateLimiting: boolean;
  jwtSecret: string;
  jwtExpiration: string;
  encryptionKey: string;
  corsOrigins: string[];
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  auditLogPath: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

export interface AuthTokenPayload {
  userId: string;
  organizationId: string;
  role: string;
  permissions: string[];
  iat: number;
  exp: number;
}

export interface AuditLog {
  id: string;
  requestId: string;
  timestamp: number;
  userId?: string;
  organizationId: string;
  action: string;
  method: string;
  path: string;
  statusCode: number;
  ipAddress: string;
  dataHash?: string;
  error?: string;
}

export interface RateLimitConfig {
  windowMs: number;
  max: number;
  keyGenerator?: (req: any) => string;
  handler?: (req: any, res: any) => void;
}

export interface EncryptionConfig {
  algorithm: string;
  keyLength: number;
}

export interface AuthorizationPolicy {
  role: string;
  permissions: string[];
  resourceRestrictions?: Record<string, string[]>;
}

export interface SecurityEvent {
  type: 'authentication_success' | 'authentication_failure' | 'authorization_failure' | 'data_access' | 'config_change' | 'security_violation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  userId?: string;
  organizationId: string;
  details: Record<string, any>;
  timestamp: number;
}

export interface ValidationSchema {
  [key: string]: {
    type: string;
    required?: boolean;
    minLength?: number;
    maxLength?: number;
    pattern?: string;
    enum?: any[];
  };
}

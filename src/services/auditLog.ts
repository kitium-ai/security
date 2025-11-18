/**
 * Audit Logging Service
 */

import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import { AuditLog, SecurityEvent } from '../types';
import { configManager } from '../config';
import { logger } from '../utils/logger';
import { encryptionService } from '../utils/encryption';

export class AuditLogService {
  private logFile: string;
  private config = configManager.getConfig();

  constructor() {
    this.logFile = this.config.auditLogPath;
    this.ensureLogDirectory();
  }

  /**
   * Ensure log directory exists
   */
  private ensureLogDirectory(): void {
    const dir = path.dirname(this.logFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Log security event
   */
  public logSecurityEvent(event: SecurityEvent): void {
    const logEntry = {
      timestamp: new Date().toISOString(),
      ...event,
    };

    try {
      fs.appendFileSync(
        this.logFile,
        JSON.stringify(logEntry) + '\n',
        'utf-8'
      );

      logger.info(`Security event logged: ${event.type}`, {
        organizationId: event.organizationId,
        severity: event.severity,
      });
    } catch (error) {
      logger.error('Failed to write security event to audit log', {
        error: (error as Error).message,
        event: event.type,
      });
    }
  }

  /**
   * Log HTTP request
   */
  public logRequest(auditLog: AuditLog): void {
    const logEntry = {
      ...auditLog,
      timestamp: Date.now(),
    };

    try {
      fs.appendFileSync(
        this.logFile,
        JSON.stringify(logEntry) + '\n',
        'utf-8'
      );

      logger.debug('Request logged', {
        requestId: auditLog.requestId,
        method: auditLog.method,
        path: auditLog.path,
      });
    } catch (error) {
      logger.error('Failed to write request to audit log', {
        error: (error as Error).message,
      });
    }
  }

  /**
   * Log data access
   */
  public logDataAccess(
    userId: string | undefined,
    organizationId: string,
    resourceId: string,
    action: string,
    dataHash: string
  ): void {
    const event: SecurityEvent = {
      type: 'data_access',
      severity: 'low',
      userId,
      organizationId,
      details: {
        resourceId,
        action,
        dataHash,
      },
      timestamp: Date.now(),
    };

    this.logSecurityEvent(event);
  }

  /**
   * Log authentication attempt
   */
  public logAuthenticationAttempt(
    userId: string,
    organizationId: string,
    success: boolean,
    ipAddress: string
  ): void {
    const event: SecurityEvent = {
      type: success ? 'authentication_success' : 'authentication_failure',
      severity: success ? 'low' : 'medium',
      userId,
      organizationId,
      details: {
        ipAddress,
      },
      timestamp: Date.now(),
    };

    this.logSecurityEvent(event);
  }

  /**
   * Log authorization failure
   */
  public logAuthorizationFailure(
    userId: string,
    organizationId: string,
    requiredPermission: string
  ): void {
    const event: SecurityEvent = {
      type: 'authorization_failure',
      severity: 'medium',
      userId,
      organizationId,
      details: {
        requiredPermission,
      },
      timestamp: Date.now(),
    };

    this.logSecurityEvent(event);
  }

  /**
   * Log security violation
   */
  public logSecurityViolation(
    organizationId: string,
    violationType: string,
    details: Record<string, any>
  ): void {
    const event: SecurityEvent = {
      type: 'security_violation',
      severity: 'high',
      organizationId,
      details: {
        violationType,
        ...details,
      },
      timestamp: Date.now(),
    };

    this.logSecurityEvent(event);
  }

  /**
   * Generate request ID
   */
  public generateRequestId(): string {
    return uuidv4();
  }

  /**
   * Get audit logs for organization
   */
  public getLogsForOrganization(organizationId: string, limit: number = 100): SecurityEvent[] {
    try {
      if (!fs.existsSync(this.logFile)) {
        return [];
      }

      const data = fs.readFileSync(this.logFile, 'utf-8');
      const logs = data
        .split('\n')
        .filter(line => line.trim())
        .map(line => JSON.parse(line))
        .filter(log => log.organizationId === organizationId)
        .slice(-limit);

      return logs;
    } catch (error) {
      logger.error('Failed to read audit logs', {
        error: (error as Error).message,
      });
      return [];
    }
  }

  /**
   * Export audit logs
   */
  public exportLogsForOrganization(
    organizationId: string,
    format: 'json' | 'csv'
  ): string {
    const logs = this.getLogsForOrganization(organizationId, 1000);

    if (format === 'json') {
      return JSON.stringify(logs, null, 2);
    }

    // CSV format
    const headers = ['timestamp', 'type', 'severity', 'userId', 'details'];
    const rows = logs.map(log => [
      log.timestamp,
      log.type,
      log.severity,
      log.userId || 'N/A',
      JSON.stringify(log.details),
    ]);

    const csv = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
    ].join('\n');

    return csv;
  }
}

export const auditLogService = new AuditLogService();

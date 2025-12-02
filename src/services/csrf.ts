/**
 * CSRF Protection Service
 * Implements Cross-Site Request Forgery protection using double-submit cookie pattern
 * and synchronizer token pattern
 */

import crypto from 'crypto';
import { logger } from '../utils/logger';

export interface CSRFToken {
  token: string;
  expiresAt: number;
}

export interface CSRFConfig {
  cookieName?: string;
  headerName?: string;
  tokenLength?: number;
  tokenExpiration?: number; // in milliseconds
  secureCookie?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
}

/**
 * CSRF Protection Service
 */
export class CSRFProtectionService {
  private tokenStore: Map<string, CSRFToken> = new Map();
  private config: Required<CSRFConfig>;

  // Cleanup interval (every 5 minutes)
  private cleanupInterval: NodeJS.Timeout;

  constructor(config: CSRFConfig = {}) {
    this.config = {
      cookieName: config.cookieName || 'XSRF-TOKEN',
      headerName: config.headerName || 'X-XSRF-TOKEN',
      tokenLength: config.tokenLength || 32,
      tokenExpiration: config.tokenExpiration || 3600000, // 1 hour
      secureCookie: config.secureCookie !== false,
      sameSite: config.sameSite || 'strict',
    };

    // Start cleanup interval
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredTokens();
    }, 300000); // 5 minutes
  }

  /**
   * Generate a CSRF token
   */
  public generateToken(sessionId?: string): CSRFToken {
    const token = crypto.randomBytes(this.config.tokenLength).toString('base64url');
    const expiresAt = Date.now() + this.config.tokenExpiration;

    const csrfToken: CSRFToken = {
      token,
      expiresAt,
    };

    // Store token with optional session binding
    const key = sessionId ? `${sessionId}:${token}` : token;
    this.tokenStore.set(key, csrfToken);

    logger.debug('CSRF token generated', {
      tokenLength: token.length,
      expiresAt: new Date(expiresAt).toISOString(),
      sessionBound: !!sessionId,
    });

    return csrfToken;
  }

  /**
   * Validate CSRF token
   */
  public validateToken(token: string, sessionId?: string): boolean {
    if (!token) {
      logger.warn('CSRF validation failed: No token provided');
      return false;
    }

    // Try both session-bound and non-session-bound keys
    const keys = sessionId ? [`${sessionId}:${token}`, token] : [token];

    for (const key of keys) {
      const storedToken = this.tokenStore.get(key);

      if (storedToken) {
        // Check if token is expired
        if (Date.now() > storedToken.expiresAt) {
          logger.warn('CSRF validation failed: Token expired', {
            expiresAt: new Date(storedToken.expiresAt).toISOString(),
          });
          this.tokenStore.delete(key);
          return false;
        }

        // Token is valid
        logger.debug('CSRF token validated successfully', {
          sessionBound: key.includes(':'),
        });
        return true;
      }
    }

    logger.warn('CSRF validation failed: Token not found');
    return false;
  }

  /**
   * Invalidate a CSRF token
   */
  public invalidateToken(token: string, sessionId?: string): void {
    const keys = sessionId ? [`${sessionId}:${token}`, token] : [token];

    for (const key of keys) {
      if (this.tokenStore.delete(key)) {
        logger.debug('CSRF token invalidated', { key });
      }
    }
  }

  /**
   * Rotate CSRF token (invalidate old and generate new)
   */
  public rotateToken(oldToken: string, sessionId?: string): CSRFToken {
    this.invalidateToken(oldToken, sessionId);
    return this.generateToken(sessionId);
  }

  /**
   * Cleanup expired tokens
   */
  private cleanupExpiredTokens(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, token] of this.tokenStore.entries()) {
      if (now > token.expiresAt) {
        this.tokenStore.delete(key);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.debug('CSRF tokens cleaned up', {
        count: cleanedCount,
        remaining: this.tokenStore.size,
      });
    }
  }

  /**
   * Get token store size (for monitoring)
   */
  public getTokenCount(): number {
    return this.tokenStore.size;
  }

  /**
   * Clear all tokens
   */
  public clearAllTokens(): void {
    this.tokenStore.clear();
    logger.info('All CSRF tokens cleared');
  }

  /**
   * Get CSRF configuration
   */
  public getConfig(): Required<CSRFConfig> {
    return { ...this.config };
  }

  /**
   * Cleanup on service shutdown
   */
  public destroy(): void {
    clearInterval(this.cleanupInterval);
    this.tokenStore.clear();
    logger.info('CSRF protection service destroyed');
  }

  /**
   * Verify double-submit cookie pattern
   * Compares cookie value with header/body value
   */
  public verifyDoubleSubmit(cookieValue: string, submittedValue: string): boolean {
    if (!cookieValue || !submittedValue) {
      logger.warn('CSRF double-submit verification failed: Missing values');
      return false;
    }

    // Use constant-time comparison to prevent timing attacks
    try {
      const isValid = crypto.timingSafeEqual(Buffer.from(cookieValue), Buffer.from(submittedValue));

      if (!isValid) {
        logger.warn('CSRF double-submit verification failed: Values do not match');
      }

      return isValid;
    } catch (error) {
      logger.warn('CSRF double-submit verification failed', {
        error: (error as Error).message,
      });
      return false;
    }
  }
}

export const csrfProtectionService = new CSRFProtectionService();

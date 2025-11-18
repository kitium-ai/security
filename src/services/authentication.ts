/**
 * Authentication Service
 */

import jwt from 'jsonwebtoken';
import bcryptjs from 'bcryptjs';
import { configManager } from '../config';
import { AuthTokenPayload, SecurityEvent } from '../types';
import { logger } from '../utils/logger';

export class AuthenticationService {
  private config = configManager.getConfig();
  private bcryptRounds = 12;

  /**
   * Generate JWT token
   */
  public generateToken(payload: Omit<AuthTokenPayload, 'iat' | 'exp'>): string {
    const token = jwt.sign(payload, this.config.jwtSecret, {
      expiresIn: this.config.jwtExpiration,
      algorithm: 'HS256',
    });

    logger.info('Token generated', {
      userId: payload.userId,
      organizationId: payload.organizationId,
    });

    return token;
  }

  /**
   * Verify JWT token
   */
  public verifyToken(token: string): AuthTokenPayload | null {
    try {
      const payload = jwt.verify(token, this.config.jwtSecret, {
        algorithms: ['HS256'],
      }) as AuthTokenPayload;

      return payload;
    } catch (error) {
      logger.warn('Token verification failed', {
        error: (error as Error).message,
      });
      return null;
    }
  }

  /**
   * Hash password
   */
  public async hashPassword(password: string): Promise<string> {
    try {
      const salt = await bcryptjs.genSalt(this.bcryptRounds);
      return await bcryptjs.hash(password, salt);
    } catch (error) {
      logger.error('Password hashing failed', { error: (error as Error).message });
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Verify password
   */
  public async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await bcryptjs.compare(password, hash);
    } catch (error) {
      logger.error('Password verification failed', { error: (error as Error).message });
      return false;
    }
  }

  /**
   * Validate token expiration
   */
  public isTokenExpired(payload: AuthTokenPayload): boolean {
    const currentTime = Math.floor(Date.now() / 1000);
    return payload.exp < currentTime;
  }

  /**
   * Refresh token
   */
  public refreshToken(oldToken: string): string | null {
    const payload = this.verifyToken(oldToken);

    if (!payload) {
      logger.warn('Token refresh failed: invalid token');
      return null;
    }

    const { userId, organizationId, role, permissions } = payload;

    const newToken = this.generateToken({
      userId,
      organizationId,
      role,
      permissions,
    });

    logger.info('Token refreshed', {
      userId,
      organizationId,
    });

    return newToken;
  }

  /**
   * Validate token structure
   */
  public validateTokenStructure(token: string): boolean {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }

    try {
      for (const part of [parts[0], parts[1]]) {
        const buffer = Buffer.from(part, 'base64');
        JSON.parse(buffer.toString('utf-8'));
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Decode token without verification
   */
  public decodeToken(token: string): AuthTokenPayload | null {
    try {
      return jwt.decode(token) as AuthTokenPayload | null;
    } catch {
      return null;
    }
  }
}

export const authenticationService = new AuthenticationService();

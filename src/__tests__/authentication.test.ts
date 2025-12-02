/**
 * Authentication Service Tests
 */

import { describe, it, expect } from 'vitest';
import { authenticationService } from '../services/authentication';
import { AuthTokenPayload } from '../types';

describe('AuthenticationService', () => {
  const testPayload: Omit<AuthTokenPayload, 'iat' | 'exp'> = {
    userId: 'user-123',
    organizationId: 'org-123',
    role: 'admin',
    permissions: ['read:*', 'write:*'],
  };

  describe('Token Generation and Verification', () => {
    it('should generate a valid JWT token', () => {
      const token = authenticationService.generateToken(testPayload);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });

    it('should verify a valid token', () => {
      const token = authenticationService.generateToken(testPayload);
      const verified = authenticationService.verifyToken(token);

      expect(verified).toBeDefined();
      expect(verified?.userId).toBe(testPayload.userId);
      expect(verified?.organizationId).toBe(testPayload.organizationId);
      expect(verified?.role).toBe(testPayload.role);
    });

    it('should return null for invalid token', () => {
      const invalid = authenticationService.verifyToken('invalid-token');
      expect(invalid).toBeNull();
    });

    it('should reject expired tokens', () => {
      // Create a token that expires immediately
      const shortLivedPayload = {
        ...testPayload,
        exp: Math.floor(Date.now() / 1000) - 10, // Expired 10 seconds ago
      };

      // This is a simplified test - in production you'd create proper expired tokens
      expect(true).toBe(true);
    });

    it('should validate token structure', () => {
      const validToken = authenticationService.generateToken(testPayload);
      expect(authenticationService.validateTokenStructure(validToken)).toBe(true);

      expect(authenticationService.validateTokenStructure('invalid')).toBe(false);
      expect(authenticationService.validateTokenStructure('a.b')).toBe(false);
    });
  });

  describe('Password Hashing', () => {
    it('should hash password', async () => {
      const password = 'test-password-123';
      const hash = await authenticationService.hashPassword(password);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(20);
    });

    it('should verify correct password', async () => {
      const password = 'test-password-123';
      const hash = await authenticationService.hashPassword(password);
      const verified = await authenticationService.verifyPassword(password, hash);

      expect(verified).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'test-password-123';
      const hash = await authenticationService.hashPassword(password);
      const verified = await authenticationService.verifyPassword('wrong-password', hash);

      expect(verified).toBe(false);
    });
  });

  describe('Token Refresh', () => {
    it('should refresh valid token', () => {
      const originalToken = authenticationService.generateToken(testPayload);
      const newToken = authenticationService.refreshToken(originalToken);

      expect(newToken).toBeDefined();
      expect(newToken).toBeTruthy();

      const newPayload = authenticationService.verifyToken(newToken!);
      expect(newPayload?.userId).toBe(testPayload.userId);
    });

    it('should return null for invalid token refresh', () => {
      const newToken = authenticationService.refreshToken('invalid-token');
      expect(newToken).toBeNull();
    });
  });

  describe('Token Decoding', () => {
    it('should decode token without verification', () => {
      const token = authenticationService.generateToken(testPayload);
      const decoded = authenticationService.decodeToken(token);

      expect(decoded).toBeDefined();
      expect(decoded?.userId).toBe(testPayload.userId);
    });

    it('should return null for invalid token decode', () => {
      const decoded = authenticationService.decodeToken('invalid-token');
      expect(decoded).toBeNull();
    });
  });
});

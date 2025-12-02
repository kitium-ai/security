/**
 * Authorization Service Tests
 */

import { describe, it, expect } from 'vitest';
import { authorizationService } from '../services/authorization';
import { AuthTokenPayload } from '../types';

describe('AuthorizationService', () => {
  const adminPayload: AuthTokenPayload = {
    userId: 'user-123',
    organizationId: 'org-123',
    role: 'admin',
    permissions: ['read:*', 'write:*', 'delete:*', 'manage:users'],
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };

  const userPayload: AuthTokenPayload = {
    userId: 'user-456',
    organizationId: 'org-123',
    role: 'user',
    permissions: ['read:own_data', 'write:own_data'],
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };

  describe('Permission Checking', () => {
    it('should grant admin all permissions', () => {
      expect(authorizationService.hasPermission(adminPayload, 'read:anything')).toBe(true);
      expect(authorizationService.hasPermission(adminPayload, 'write:anything')).toBe(true);
      expect(authorizationService.hasPermission(adminPayload, 'manage:users')).toBe(true);
    });

    it('should check specific permissions', () => {
      expect(authorizationService.hasPermission(userPayload, 'read:own_data')).toBe(true);
      expect(authorizationService.hasPermission(userPayload, 'write:own_data')).toBe(true);
      expect(authorizationService.hasPermission(userPayload, 'manage:users')).toBe(false);
    });

    it('should check wildcard permissions', () => {
      expect(authorizationService.hasPermission(adminPayload, 'read:any_resource')).toBe(true);
      expect(authorizationService.hasPermission(adminPayload, 'write:any_resource')).toBe(true);
    });
  });

  describe('Multiple Permissions', () => {
    it('should check if user has any required permission', () => {
      const result = authorizationService.hasAnyPermission(userPayload, [
        'write:other_data',
        'read:own_data',
      ]);
      expect(result).toBe(true);
    });

    it('should check if user has all required permissions', () => {
      const result = authorizationService.hasAllPermissions(userPayload, [
        'read:own_data',
        'write:own_data',
      ]);
      expect(result).toBe(true);

      const result2 = authorizationService.hasAllPermissions(userPayload, [
        'read:own_data',
        'manage:users',
      ]);
      expect(result2).toBe(false);
    });
  });

  describe('Role-Based Access', () => {
    it('should check role access', () => {
      expect(authorizationService.canAccessByRole('admin', ['admin', 'manager'])).toBe(true);
      expect(authorizationService.canAccessByRole('user', ['admin', 'manager'])).toBe(false);
    });

    it('should enforce minimum role requirement', () => {
      expect(authorizationService.enforceMinimumRole('admin', 'user')).toBe(true);
      expect(authorizationService.enforceMinimumRole('user', 'admin')).toBe(false);
      expect(authorizationService.enforceMinimumRole('manager', 'user')).toBe(true);
    });
  });

  describe('Resource Access', () => {
    it('should check resource-level access', () => {
      expect(authorizationService.canAccessResource(userPayload, 'resource-123', 'read')).toBe(
        true
      );
      expect(authorizationService.canAccessResource(userPayload, 'resource-123', 'manage')).toBe(
        false
      );
    });
  });

  describe('Policy Management', () => {
    it('should get permissions for role', () => {
      const adminPermissions = authorizationService.getPermissionsForRole('admin');
      expect(adminPermissions.length).toBeGreaterThan(0);
      expect(adminPermissions).toContain('manage:users');
    });

    it('should register custom policy', () => {
      authorizationService.registerPolicy({
        role: 'custom-role',
        permissions: ['read:custom_resource', 'write:custom_resource'],
      });

      const permissions = authorizationService.getPermissionsForRole('custom-role');
      expect(permissions).toContain('read:custom_resource');
    });

    it('should get all policies', () => {
      const policies = authorizationService.getAllPolicies();
      expect(Object.keys(policies).length).toBeGreaterThan(0);
      expect('admin' in policies).toBe(true);
    });
  });
});

/**
 * Authorization Service
 */

import { AuthTokenPayload, AuthorizationPolicy } from '../types';
import { logger } from '../utils/logger';

export class AuthorizationService {
  private policies: Map<string, AuthorizationPolicy> = new Map();

  constructor() {
    this.initializeDefaultPolicies();
  }

  /**
   * Initialize default role-based policies
   */
  private initializeDefaultPolicies(): void {
    this.registerPolicy({
      role: 'admin',
      permissions: [
        'read:*',
        'write:*',
        'delete:*',
        'manage:users',
        'manage:roles',
        'manage:audit-logs',
        'manage:security-policies',
      ],
    });

    this.registerPolicy({
      role: 'manager',
      permissions: [
        'read:*',
        'write:own_data',
        'manage:team',
        'view:audit-logs',
      ],
    });

    this.registerPolicy({
      role: 'user',
      permissions: [
        'read:own_data',
        'write:own_data',
        'view:own_profile',
      ],
    });

    this.registerPolicy({
      role: 'guest',
      permissions: [
        'read:public_data',
      ],
    });
  }

  /**
   * Register a new authorization policy
   */
  public registerPolicy(policy: AuthorizationPolicy): void {
    this.policies.set(policy.role, policy);
    logger.debug('Authorization policy registered', { role: policy.role });
  }

  /**
   * Check if user has permission
   */
  public hasPermission(
    tokenPayload: AuthTokenPayload,
    requiredPermission: string
  ): boolean {
    // Admin always has access
    if (tokenPayload.role === 'admin') {
      return true;
    }

    // Check if permission is in token
    if (tokenPayload.permissions.includes(requiredPermission)) {
      return true;
    }

    // Check for wildcard permissions (e.g., 'read:*')
    const [action, resource] = requiredPermission.split(':');
    const wildcardPermission = `${action}:*`;

    if (tokenPayload.permissions.includes(wildcardPermission)) {
      return true;
    }

    logger.warn('Permission denied', {
      userId: tokenPayload.userId,
      requiredPermission,
      userPermissions: tokenPayload.permissions,
    });

    return false;
  }

  /**
   * Check if user has any of the required permissions
   */
  public hasAnyPermission(
    tokenPayload: AuthTokenPayload,
    requiredPermissions: string[]
  ): boolean {
    return requiredPermissions.some(permission =>
      this.hasPermission(tokenPayload, permission)
    );
  }

  /**
   * Check if user has all required permissions
   */
  public hasAllPermissions(
    tokenPayload: AuthTokenPayload,
    requiredPermissions: string[]
  ): boolean {
    return requiredPermissions.every(permission =>
      this.hasPermission(tokenPayload, permission)
    );
  }

  /**
   * Check role-based access
   */
  public canAccessByRole(userRole: string, requiredRoles: string[]): boolean {
    return requiredRoles.includes(userRole);
  }

  /**
   * Get permissions for a role
   */
  public getPermissionsForRole(role: string): string[] {
    const policy = this.policies.get(role);
    return policy ? policy.permissions : [];
  }

  /**
   * Check resource-level access
   */
  public canAccessResource(
    tokenPayload: AuthTokenPayload,
    resourceId: string,
    action: string
  ): boolean {
    const permission = `${action}:${resourceId}`;

    // Check exact permission
    if (tokenPayload.permissions.includes(permission)) {
      return true;
    }

    // Check wildcard permission
    const wildcardPermission = `${action}:*`;
    if (tokenPayload.permissions.includes(wildcardPermission)) {
      return true;
    }

    // Check own data access
    if (action === 'read' || action === 'write') {
      const ownPermission = `${action}:own_data`;
      if (tokenPayload.permissions.includes(ownPermission)) {
        // Simplified: in production, verify resource belongs to user
        return true;
      }
    }

    return false;
  }

  /**
   * Enforce minimum role requirement
   */
  public enforceMinimumRole(userRole: string, minimumRole: string): boolean {
    const roleHierarchy: Record<string, number> = {
      guest: 0,
      user: 1,
      manager: 2,
      admin: 3,
    };

    const userRoleLevel = roleHierarchy[userRole] ?? -1;
    const minimumRoleLevel = roleHierarchy[minimumRole] ?? -1;

    return userRoleLevel >= minimumRoleLevel;
  }

  /**
   * Get all registered policies
   */
  public getAllPolicies(): Record<string, AuthorizationPolicy> {
    const policies: Record<string, AuthorizationPolicy> = {};
    this.policies.forEach((policy, role) => {
      policies[role] = policy;
    });
    return policies;
  }
}

export const authorizationService = new AuthorizationService();

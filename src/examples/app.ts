/**
 * Example Express Application using Security Middleware
 */

import express, { Express, Request, Response } from 'express';
import {
  initializeSecurityMiddleware,
  authenticationService,
  authorizationService,
  auditLogService,
} from '../index';

let app: Express;
let factory: any;

/**
 * Initialize Express app with security middleware
 */
async function initializeApp(): Promise<Express> {
  const security = await initializeSecurityMiddleware();
  factory = security.factory;

  app = express();
  app.use(express.json());

  // Apply security middleware globally
  app.use(factory.createRequestIdMiddleware());
  app.use(factory.createHelmetMiddleware());
  app.use(factory.createCorsMiddleware());
  app.use(factory.createRateLimitMiddleware());
  app.use(factory.createAuditLoggingMiddleware());

  // Public routes
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
    });
  });

  // Authentication endpoint
  app.post('/auth/login', async (req: Request, res: Response): Promise<void> => {
    const context = req.securityContext;

    if (!context) {
      res.status(500).json({ error: 'Security context not initialized' });
      return;
    }

    // Validate request
    const { userId, organizationId, role, password } = req.body;

    if (!userId || !organizationId || !role || !password) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }

    // In production, verify password against database
    if (password !== 'demo-password') {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Generate token
    const token = authenticationService.generateToken({
      userId,
      organizationId,
      role,
      permissions: authorizationService.getPermissionsForRole(role),
    });

    res.json({
      token,
      expiresIn: '24h',
      requestId: context.requestId,
    });
  });

  // Protected route - requires authentication
  app.get(
    '/api/profile',
    factory.createAuthenticationMiddleware(),
    (req: Request, res: Response): void => {
      const context = req.securityContext;
      const payload = req.tokenPayload;

      if (!context || !payload) {
        res.status(500).json({ error: 'Security context not initialized' });
        return;
      }

      res.json({
        userId: payload.userId,
        organizationId: payload.organizationId,
        role: payload.role,
        permissions: payload.permissions,
        requestId: context.requestId,
      });
    }
  );

  // Protected route - requires specific permission
  app.get(
    '/api/admin/users',
    factory.createAuthenticationMiddleware(),
    factory.createAuthorizationMiddleware(['manage:users']),
    (req: Request, res: Response) => {
      const context = req.securityContext;

      res.json({
        users: [
          { id: 'user1', name: 'John Doe', role: 'user' },
          { id: 'user2', name: 'Jane Smith', role: 'manager' },
        ],
        requestId: context?.requestId,
      });
    }
  );

  // Protected route - requires role
  app.post(
    '/api/resources',
    factory.createAuthenticationMiddleware(),
    factory.createAuthorizationMiddleware(['write:*']),
    (req: Request, res: Response) => {
      const context = req.securityContext;

      res.status(201).json({
        resourceId: 'resource-123',
        created: true,
        requestId: context?.requestId,
      });
    }
  );

  // Route to get audit logs (admin only)
  app.get(
    '/api/admin/audit-logs',
    factory.createAuthenticationMiddleware(),
    factory.createAuthorizationMiddleware(['manage:audit-logs']),
    (req: Request, res: Response): void => {
      const context = req.securityContext;

      if (!context) {
        res.status(500).json({ error: 'Security context not initialized' });
        return;
      }

      const logs = auditLogService.getLogsForOrganization(context.organizationId);

      res.json({
        logs,
        count: logs.length,
        requestId: context.requestId,
      });
    }
  );

  // Error handling
  app.use((err: any, req: Request, res: Response) => {
    const context = req.securityContext;

    res.status(err.status || 500).json({
      error: err.message || 'Internal server error',
      requestId: context?.requestId,
    });
  });

  return app;
}

/**
 * Start the server
 */
async function startServer(port: number = 3000): Promise<void> {
  const app = await initializeApp();

  app.listen(port, () => {
    console.log(`Security middleware server running on http://localhost:${port}`);
  });
}

// Export for testing
export { initializeApp };

// Start if run directly
if (require.main === module) {
  startServer();
}

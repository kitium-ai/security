/**
 * Comprehensive Security Example
 * Demonstrates all security features including HTTPS, CSRF, sanitization, and more
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import { securityMiddlewareFactory } from '../middleware/factory';
import { tlsConfigurationService } from '../server/https';
import { authenticationService } from '../services/authentication';
import { inputSanitizer } from '../utils/sanitize';
import { sqlInjectionExamples } from '../database/sqlInjectionPrevention';

const app = express();

// Parse JSON and cookies
app.use(bodyParser.json());
app.use(cookieParser());

// 1. REQUEST ID MIDDLEWARE (first)
app.use(securityMiddlewareFactory.createRequestIdMiddleware());

// 2. SECURITY HEADERS (Helmet)
app.use(securityMiddlewareFactory.createHelmetMiddleware());

// 3. CORS MIDDLEWARE
app.use(securityMiddlewareFactory.createCorsMiddleware());

// 4. RATE LIMITING
app.use(securityMiddlewareFactory.createRateLimitMiddleware());

// 5. SECURE COOKIE MIDDLEWARE
app.use(securityMiddlewareFactory.createSecureCookieMiddleware());

// 6. INPUT SANITIZATION (before validation)
app.use(
  securityMiddlewareFactory.createSanitizationMiddleware({
    sanitizeBody: true,
    sanitizeQuery: true,
    sanitizeParams: true,
    maxLength: 10000,
    detectMalicious: true,
  })
);

// 7. CSRF PROTECTION (for state-changing operations)
app.use(
  securityMiddlewareFactory.createCsrfMiddleware({
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  })
);

// 8. AUDIT LOGGING
app.use(securityMiddlewareFactory.createAuditLoggingMiddleware());

// =============================================================================
// PUBLIC ENDPOINTS
// =============================================================================

/**
 * Health check endpoint
 */
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

/**
 * Get CSRF token (for SPA clients)
 */
app.get('/api/csrf-token', (req, res) => {
  // Token is automatically set in cookie by CSRF middleware
  const token = req.cookies['XSRF-TOKEN'];
  res.json({ csrfToken: token });
});

/**
 * Login endpoint (no CSRF required)
 */
app.post('/api/auth/login', async (req, res): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Sanitize inputs
    inputSanitizer.sanitizeEmail(email);

    // In production, verify password against database
    // This is just an example
    const isValid = password === 'demo-password';

    if (!isValid) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Generate JWT token
    const token = authenticationService.generateToken({
      userId: 'user-123',
      organizationId: req.securityContext?.organizationId || 'default',
      role: 'user',
      permissions: ['read:data', 'write:data'],
    });

    // Set secure HTTP-only cookie with token
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 86400000, // 24 hours
    });

    res.json({
      message: 'Login successful',
      token,
      expiresIn: 86400,
    });
  } catch {
    res.status(500).json({ error: 'Login failed' });
  }
});

// =============================================================================
// PROTECTED ENDPOINTS (require authentication)
// =============================================================================

/**
 * Protected route - requires authentication
 */
app.get(
  '/api/protected',
  securityMiddlewareFactory.createAuthenticationMiddleware(),
  (req, res) => {
    res.json({
      message: 'This is a protected route',
      user: req.tokenPayload,
    });
  }
);

/**
 * Admin route - requires authentication + admin role
 */
app.get(
  '/api/admin',
  securityMiddlewareFactory.createAuthenticationMiddleware(),
  securityMiddlewareFactory.createAuthorizationMiddleware(['admin:*']),
  (req, res) => {
    res.json({
      message: 'This is an admin-only route',
      user: req.tokenPayload,
    });
  }
);

/**
 * Create user endpoint with validation and sanitization
 */
app.post(
  '/api/users',
  securityMiddlewareFactory.createAuthenticationMiddleware(),
  securityMiddlewareFactory.createAuthorizationMiddleware(['write:users']),
  securityMiddlewareFactory.createValidationMiddleware({
    username: {
      type: 'string',
      required: true,
      minLength: 3,
      maxLength: 50,
      pattern: '^[a-zA-Z0-9_-]+$',
    },
    email: {
      type: 'email',
      required: true,
    },
    age: {
      type: 'number',
      required: false,
    },
  }),
  (req, res) => {
    const { username, email, age } = req.body;

    // Additional sanitization for specific fields
    const sanitizedUsername = inputSanitizer.sanitizeForDatabase(username);
    const sanitizedEmail = inputSanitizer.sanitizeEmail(email);

    // Example of SQL injection prevention
    // In production, use an ORM or parameterized queries
    const { query, params } = sqlInjectionExamples.safeInsert(
      sanitizedUsername,
      sanitizedEmail,
      'hashed_password_here'
    );

    // Log what would be executed
    console.log('Safe SQL query:', query);
    console.log('Parameters:', params);

    res.status(201).json({
      message: 'User created successfully',
      user: {
        username: sanitizedUsername,
        email: sanitizedEmail,
        age,
      },
    });
  }
);

/**
 * File upload endpoint with sanitization
 */
app.post(
  '/api/upload',
  securityMiddlewareFactory.createAuthenticationMiddleware(),
  (req, res): void => {
    const { filename, url } = req.body;

    // Sanitize filename to prevent path traversal
    const safeFilename = inputSanitizer.sanitizeFilename(filename);

    // Sanitize URL to prevent javascript: protocol injection
    const safeUrl = inputSanitizer.sanitizeURL(url);

    if (!safeFilename || !safeUrl) {
      res.status(400).json({
        error: 'Invalid filename or URL',
      });
      return;
    }

    res.json({
      message: 'File upload accepted',
      filename: safeFilename,
      url: safeUrl,
    });
  }
);

/**
 * XSS Prevention Example
 */
app.post('/api/comments', (req, res): void => {
  const { comment } = req.body;

  // Detect malicious patterns
  const detection = inputSanitizer.detectMaliciousPatterns(comment);

  if (detection.isSuspicious) {
    res.status(400).json({
      error: 'Potentially malicious content detected',
      patterns: detection.patterns,
    });
    return;
  }

  // Sanitize for safe storage
  const sanitizedComment = inputSanitizer.sanitize(comment, {
    stripScripts: true,
    stripEventHandlers: true,
    maxLength: 1000,
  });

  res.json({
    message: 'Comment saved',
    comment: sanitizedComment,
  });
});

/**
 * SQL Injection Prevention Example
 */
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;

  // WRONG WAY (vulnerable)
  // const badQuery = `SELECT * FROM users WHERE id = '${userId}'`;

  // RIGHT WAY (safe)
  const { query, params } = sqlInjectionExamples.safeParameterizedQuery(userId);

  res.json({
    message: 'This query is safe from SQL injection',
    query,
    params,
    note: 'In production, execute this with your database client using parameterized queries',
  });
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Error:', err);

  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    requestId: req.securityContext?.requestId,
  });
});

// =============================================================================
// START SERVER
// =============================================================================

/**
 * Start HTTP server (development only)
 */
export function startHTTPServer(port: number = 3000) {
  app.listen(port, () => {
    console.log(`\n🔓 HTTP Server running on http://localhost:${port}`);
    console.log('⚠️  WARNING: HTTP is not secure. Use HTTPS in production!\n');
  });
}

/**
 * Start HTTPS server (production)
 */
export function startHTTPSServer(tlsConfig: {
  keyPath: string;
  certPath: string;
  port?: number;
  redirectHttpToHttps?: boolean;
}) {
  // Validate TLS configuration
  const validation = tlsConfigurationService.validateTLSConfig(tlsConfig);

  if (!validation.valid) {
    console.error('TLS configuration invalid:');
    validation.errors.forEach((err) => console.error(`  - ${err}`));
    process.exit(1);
  }

  // Setup HTTPS server with HTTP redirect
  const { httpsServer, httpServer } = tlsConfigurationService.setupSecureServer(app, tlsConfig);

  console.log(`\n🔒 HTTPS Server running on https://localhost:${tlsConfig.port || 443}`);

  if (httpServer) {
    console.log(`🔀 HTTP redirect server running (redirecting to HTTPS)`);
  }

  console.log('\n✅ All security features enabled:');
  console.log('  - HTTPS/TLS encryption');
  console.log('  - Security headers (CSP, HSTS, X-Frame-Options, etc.)');
  console.log('  - CORS protection');
  console.log('  - CSRF protection');
  console.log('  - Rate limiting');
  console.log('  - Input sanitization');
  console.log('  - XSS prevention');
  console.log('  - SQL injection prevention');
  console.log('  - Secure cookies');
  console.log('  - Audit logging\n');

  return { httpsServer, httpServer };
}

// Export app for testing
export default app;

// Example usage:
if (require.main === module) {
  // For development (HTTP)
  startHTTPServer(3000);

  // For production (HTTPS) - uncomment and configure paths
  /*
  startHTTPSServer({
    keyPath: './certs/key.pem',
    certPath: './certs/cert.pem',
    port: 443,
    redirectHttpToHttps: true,
  });
  */
}

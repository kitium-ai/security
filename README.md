# Enterprise Security Middleware

A production-ready, enterprise-grade security middleware providing consistent secure environments across organizations.

> Looking for an enterprise gap analysis and roadmap? See [Enterprise Readiness Evaluation](docs/ENTERPRISE_READINESS.md) for a comparison against big-tech expectations and recommended improvements.

## Features

### 🔐 Core Security Features

- **Authentication & Authorization** - JWT-based authentication with role-based access control (RBAC)
- **Encryption & Data Protection** - AES-256-GCM encryption for sensitive data
- **Audit Logging** - Comprehensive audit trail for compliance and security monitoring
- **Rate Limiting & DDoS Protection** - Request rate limiting per organization
- **CORS & Security Headers** - Helmet integration for secure HTTP headers
- **Request Validation** - Input validation using Joi schema

### 🏢 Enterprise Features

- **Multi-Tenant Support** - Organize-scoped security context
- **Role-Based Access Control** - Flexible permission system with wildcards
- **Identity Federation** - OIDC/SAML adapters plus SCIM sync powered by `@kitium-ai/auth`
- **Policy-as-Code** - OPA/Cedar-inspired PDP middleware with tenant bundles
- **Security Events** - Detailed security event tracking
- **Audit Exports** - Export audit logs in JSON/CSV format with response signing and retention checks
- **Configuration Management** - Centralized security configuration with secret manager abstractions
- **Environment-Aware** - Development, staging, and production modes
- **Observability** - OpenTelemetry spans, metrics, and liveness/readiness probes
- **Network Hardening** - mTLS, IP allow/deny lists, payload size guard, file scan hooks

## Installation

```bash
npm install @enterprise/security-middleware
```

## Quick Start

### 1. Setup Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and set your security keys:

```
JWT_SECRET=your-super-secret-key-minimum-32-characters-long!
ENCRYPTION_KEY=your-encryption-key-minimum-32-characters-long!
RESPONSE_SIGNING_KEY=rotate-me
KMS_KEY_ID=alias/security
```

### 2. Initialize the Enterprise Suite with Secure Defaults

```typescript
import express from 'express';
import { createSecuritySuite } from '@enterprise/security-middleware';

const app = express();
app.use(express.json());

const suite = createSecuritySuite({
  presets: ['enterprise'],
  identityProviders: [
    {
      mode: 'oidc',
      issuer: 'https://login.example.com',
      clientId: process.env.CLIENT_ID!,
      clientSecret: process.env.CLIENT_SECRET,
      scopes: ['openid', 'profile', 'email'],
    },
  ],
  policyBackend: 'opa',
});

suite.apply(app);
suite.requirePolicy('read', 'health');

// Apply all guardrails (context, mTLS, rate limits, CORS, helmet, audit, tracing, metrics)
suite.middleware && suite; // just ensures tree-shaking keeps middleware exports
```

### 3. Protect Routes with Policies, Step-Up, and Consent Scopes

```typescript
import { securityMiddlewareFactory } from '@enterprise/security-middleware';

// Protect with authentication
app.get('/api/profile', securityMiddlewareFactory.createAuthenticationMiddleware(), (req, res) => {
  res.json({ user: req.tokenPayload });
});

// Protect with specific permissions
app.post(
  '/api/admin/users',
  securityMiddlewareFactory.createAuthenticationMiddleware(),
  suite.requireConsent(['profile.read']),
  (req, res) => res.json({ user: req.tokenPayload })
);
```

## API Documentation

### Services

#### AuthenticationService

- `generateToken(payload)` - Generate JWT token
- `verifyToken(token)` - Verify token validity
- `hashPassword(password)` - Hash password securely
- `verifyPassword(password, hash)` - Verify password
- `refreshToken(token)` - Refresh expired token

#### AuthorizationService

- `hasPermission(tokenPayload, permission)` - Check single permission
- `hasAllPermissions(tokenPayload, permissions)` - Check all permissions
- `canAccessByRole(role, requiredRoles)` - Check role access
- `enforceMinimumRole(userRole, minimumRole)` - Enforce role hierarchy

#### EncryptionService

- `encrypt(data)` - Encrypt data with AES-256-GCM
- `decrypt(encrypted, iv, authTag)` - Decrypt data
- `hash(data)` - Hash data (SHA256)
- `generateToken()` - Generate random token

#### AuditLogService

- `logSecurityEvent(event)` - Log security event
- `logRequest(auditLog)` - Log HTTP request
- `logDataAccess(...)` - Log data access
- `logAuthenticationAttempt(...)` - Log auth attempt
- `getLogsForOrganization(orgId)` - Retrieve logs

#### IdentityFederationService

- `createOidcMiddleware(provider)` - Plug-and-play OIDC login using `@kitium-ai/auth`
- `createSamlMiddleware(provider)` - Enterprise SAML adapter
- `handleScimSync(event)` - SCIM provisioning callback handler
- `requireConsentScopes(scopes)` - Enforce fine-grained consent gates
- `requireStepUp(level)` - Require MFA/strong auth for sensitive routes

#### PolicyEngineService

- `middleware(action, resource)` - Declarative PDP middleware (OPA/Cedar style)
- `loadBundle(tenant, bundle)` - Load per-tenant policies and obligations
- `setBackend(backend)` - Choose `opa`, `cedar`, or `local` evaluation

#### ObservabilityService

- `tracingMiddleware()` - Emit OpenTelemetry spans per request
- `metricsMiddleware()` - Emit structured metrics logs
- `readinessMiddleware()` / `livenessMiddleware()` - Health endpoints

#### NetworkProtectionService

- `requireMutualTLS()` - Enforce client certificates
- `enforceIpPolicy()` - Allow/deny lists
- `bodySizeGuard()` - Reject oversized payloads
- `signResponse()` - HMAC sign responses for integrity
- `fileScanMiddleware(scanner)` - Hook external malware scanners

#### KeyManagementService

- `rotateJwks()` - Automatic JWKS rotation
- `envelopeEncrypt(buffer)` / `envelopeDecrypt(payload)` - KMS-style envelope encryption
- `revokeToken(jti)` / `isRevoked(jti)` - Replay protection

#### SecretProviderService

- `getSecret(key)` - Resolve secrets from configured provider namespace
- `rotateSecret(key, value)` - Rotate cached secrets programmatically

#### DataGovernanceService

- `classify(data)` - Tag PII fields and mask values
- `enforceRetention(timestamp)` - TTL enforcement for audit retention

#### CLI Utilities

- `generateConfigTemplate(destination?)` - Emit hardened `.env` template
- `rotateKeys()` - Rotate JWKS keys for signing/verification
- `validateEnvironment()` - Config validation with actionable errors

### Middleware

#### Request ID Middleware

Adds unique request ID to each request for tracking.

```typescript
app.use(factory.createRequestIdMiddleware());
```

#### Helmet Middleware

Applies secure HTTP headers.

```typescript
app.use(factory.createHelmetMiddleware());
```

#### CORS Middleware

Configurable CORS policy.

```typescript
app.use(factory.createCorsMiddleware());
```

#### Rate Limiting

Per-organization rate limiting.

```typescript
app.use(factory.createRateLimitMiddleware());
```

#### Authentication

JWT-based authentication.

```typescript
app.use(factory.createAuthenticationMiddleware());
```

#### Authorization

Permission-based access control.

```typescript
app.use(factory.createAuthorizationMiddleware(['read:*', 'write:own_data']));
```

#### Request Validation

Input validation middleware.

```typescript
const schema = {
  email: { type: 'email', required: true },
  password: { type: 'string', required: true, minLength: 8 },
};
app.post('/register', factory.createValidationMiddleware(schema));
```

## Configuration

### Environment Variables

| Variable                  | Default               | Description                                  |
| ------------------------- | --------------------- | -------------------------------------------- |
| `NODE_ENV`                | development           | Environment (development/staging/production) |
| `JWT_SECRET`              | N/A                   | JWT signing secret (min 32 chars)            |
| `JWT_EXPIRATION`          | 24h                   | Token expiration time                        |
| `ENCRYPTION_KEY`          | N/A                   | Encryption key (min 32 chars)                |
| `CORS_ORIGINS`            | http://localhost:3000 | Comma-separated CORS origins                 |
| `RATE_LIMIT_WINDOW_MS`    | 900000                | Rate limit window (ms)                       |
| `RATE_LIMIT_MAX_REQUESTS` | 100                   | Max requests per window                      |
| `AUDIT_LOG_PATH`          | ./logs/audit.log      | Audit log file path                          |
| `LOG_LEVEL`               | info                  | Logging level                                |

### Programmatic Configuration

```typescript
import { configManager } from '@enterprise/security-middleware';

const config = configManager.getConfig();
configManager.updateConfig({
  enableEncryption: true,
  rateLimitMaxRequests: 200,
});

// Validate configuration
const validation = configManager.validateConfig();
if (!validation.valid) {
  console.error(validation.errors);
}
```

## Authorization Policies

### Default Roles

**Admin**

- All permissions (`read:*`, `write:*`, `delete:*`)
- Can manage users and security policies

**Manager**

- Read all data (`read:*`)
- Write own data (`write:own_data`)
- Manage team members

**User**

- Read own data (`read:own_data`)
- Write own data (`write:own_data`)

**Guest**

- Read public data only

### Custom Permissions

Register custom policies:

```typescript
import { authorizationService } from '@enterprise/security-middleware';

authorizationService.registerPolicy({
  role: 'analyst',
  permissions: ['read:reports', 'read:analytics', 'write:own_reports'],
});
```

### Permission Format

- `action:resource` - Specific resource access
- `action:*` - Wildcard (all resources)
- `action:own_data` - User's own data
- Supported actions: `read`, `write`, `delete`, `manage`

## Security Event Types

- `authentication_success` - Successful login
- `authentication_failure` - Failed login attempt
- `authorization_failure` - Permission denied
- `data_access` - User accessed data
- `config_change` - Security config modified
- `security_violation` - Suspicious activity detected

## Examples

### Login Flow

```typescript
// 1. User login
app.post('/auth/login', async (req, res) => {
  const { userId, password, organizationId } = req.body;

  // Verify credentials
  const user = await getUserFromDB(userId);
  const valid = await authenticationService.verifyPassword(password, user.hash);

  if (!valid) {
    auditLogService.logAuthenticationAttempt(userId, organizationId, false, req.ip);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate token
  const token = authenticationService.generateToken({
    userId,
    organizationId,
    role: user.role,
    permissions: authorizationService.getPermissionsForRole(user.role),
  });

  auditLogService.logAuthenticationAttempt(userId, organizationId, true, req.ip);
  res.json({ token });
});

// 2. Use token in requests
// Header: Authorization: Bearer <token>
```

### Protected Data Access

```typescript
app.get('/api/data/:id', factory.createAuthenticationMiddleware(), (req, res) => {
  const context = req.securityContext;
  const payload = req.tokenPayload;

  // Log data access
  auditLogService.logDataAccess(
    payload.userId,
    context.organizationId,
    req.params.id,
    'read',
    encryptionService.hash(JSON.stringify(data))
  );

  res.json(data);
});
```

## Testing

Run tests:

```bash
npm test
```

Run tests with coverage:

```bash
npm run test -- --coverage
```

## Production Deployment

### Security Checklist

- [ ] Set strong JWT_SECRET and ENCRYPTION_KEY
- [ ] Use NODE_ENV=production
- [ ] Set HTTPS URLs in CORS_ORIGINS
- [ ] Configure audit logging with persistent storage
- [ ] Set appropriate LOG_LEVEL
- [ ] Enable rate limiting with production thresholds
- [ ] Use environment-specific secrets management
- [ ] Enable encryption for sensitive data
- [ ] Review and customize authorization policies
- [ ] Set up monitoring and alerting on security events

### Secrets Management

For production, use a secrets management system:

```typescript
// Example with AWS Secrets Manager
import AWS from 'aws-sdk';

const secretsManager = new AWS.SecretsManager();

async function getSecrets() {
  const secret = await secretsManager
    .getSecretValue({
      SecretId: 'enterprise-security-middleware',
    })
    .promise();

  return JSON.parse(secret.SecretString);
}
```

## Audit Log Format

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "type": "data_access",
  "severity": "low",
  "userId": "user-123",
  "organizationId": "org-456",
  "details": {
    "resourceId": "data-789",
    "action": "read",
    "dataHash": "abc123..."
  }
}
```

## Troubleshooting

### Invalid Token

Ensure JWT_SECRET is properly configured and hasn't changed.

### Rate Limiting Issues

Check RATE_LIMIT_WINDOW_MS and RATE_LIMIT_MAX_REQUESTS settings.

### Encryption Errors

Verify ENCRYPTION_KEY is at least 32 characters long.

### Missing Logs

Check AUDIT_LOG_PATH permissions and disk space.

## Contributing

Please submit issues and pull requests to improve the security middleware.

## License

MIT

## Support

For support, documentation, and examples visit the [documentation site](https://docs.example.com).

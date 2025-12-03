---
'@kitiumai/security-middleware': major
---

- Add enterprise-grade identity federation via `@kitium-ai/auth` (OIDC, SAML, SCIM) with consent and step-up middleware.- Introduce policy-as-code PDP middleware with per-tenant bundles and route helpers.- Add KMS-style key management (envelope encryption, JWKS rotation, token revocation) and secret provider abstraction.- Deliver OpenTelemetry tracing, metrics logging, readiness/liveness endpoints, and response signing guardrails.- Provide network hardening (mTLS, IP controls, payload limits, file scanning hooks) plus data governance utilities.- Ship developer ergonomics: `applySecureDefaults`/`createSecuritySuite`, CLI helpers, and expanded README API references.

# Changelog

Brief log of notable changes, grouped by theme — not a full commit history
(see `git log` for that). New entries get appended under the section they
fit best; add a new section if none fits.

## Auth

- Pin ordinary access-token verification to RS256. Explicit
  `token_use: access` is preferred, while signed, unexpired legacy access
  tokens without the discriminator remain valid during rollout; export and
  refresh token shapes cannot be used as normal API tokens.
- Validate required identity and optional regional JWT claims at runtime before
  provisioning users. Invalid claims now receive the existing invalid-token
  response, while provisioning failures propagate to the application error
  handler.
- Reject timezone claims that are strings but not valid IANA timezone
  identifiers, while continuing to accept valid identifiers and `null`.
- Initial release: `createAuthMiddleware({ jwksUrl, issuer, onUserSeen })`
  (JWKS-based JWT verification, `requireAuth`/`requireAdmin`) and
  `createCorsMiddleware({ allowedOrigins })`, extracted from kuvert's
  `api/src/middleware/auth.ts` and CORS setup so every backend service on
  the platform shares the exact same logic instead of copy-pasting it.

## CORS

- Allow `PATCH` requests and preflights from configured origins.

## Notifications

- Harden the notification outbox runtime with upfront endpoint, credential, and
  numeric configuration validation; bounded sanitized retries for timeouts and
  transport failures; non-blocking response-body cancellation; timer/date
  overflow guards; typed stale fenced settlements; and stop/restart polling
  whose generations cannot overlap or adopt one another's abort controller.
- Add a versioned, domain-agnostic notification envelope, UUID transport ID
  schemas, canonical HMAC-SHA-256 request signing and verification, response
  classification, `Retry-After` parsing, and full-jitter exponential backoff.

## Data export

- Add a strict version 1 JSON export envelope plus RS256/JWKS export delegation
  verification with exact issuer, service audience, token-use, scope, identity,
  job, JWT ID, and expiration validation.
- Add mixed export-auth verification and Hono middleware that accepts full
  access tokens or exact service delegations and exposes only a minimal typed
  export principal.

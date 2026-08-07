# Changelog

Brief log of notable changes, grouped by theme — not a full commit history
(see `git log` for that). New entries get appended under the section they
fit best; add a new section if none fits.

## Auth

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

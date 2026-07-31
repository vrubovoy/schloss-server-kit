# Changelog

Brief log of notable changes, grouped by theme — not a full commit history
(see `git log` for that). New entries get appended under the section they
fit best; add a new section if none fits.

## Auth

- Initial release: `createAuthMiddleware({ jwksUrl, issuer, onUserSeen })`
  (JWKS-based JWT verification, `requireAuth`/`requireAdmin`) and
  `createCorsMiddleware({ allowedOrigins })`, extracted from kuvert's
  `api/src/middleware/auth.ts` and CORS setup so every backend service on
  the platform shares the exact same logic instead of copy-pasting it.

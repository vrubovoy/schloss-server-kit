# Security Policy

## Supported versions

Only the latest commit on `main` is supported — there are no maintained
release branches, and this package isn't published to any registry
(consumers link it as a git submodule).

## Reporting a vulnerability

Please do not open a public issue for security vulnerabilities. Instead,
use GitHub's private reporting flow:

1. Go to the [Security tab](../../security) of this repository.
2. Click "Report a vulnerability".
3. Describe the issue, including reproduction steps if you have them.

This is a small, mostly-solo project, so response time is best-effort, not
contractual — but you can expect an initial reply within a few days.

## Scope

This package's `createAuthMiddleware` verifies every backend service's
incoming JWTs, and `createCorsMiddleware` gates which origins each service
accepts cross-origin requests from — a vulnerability here (a JWT forgery/
verification bypass, or a CORS misconfiguration that widens an allowlist)
has platform-wide reach across every service that consumes this kit. In
scope: anything in `src/auth.ts`/`src/cors.ts` that could let an
unauthenticated or wrongly-scoped request be treated as authenticated or
same-origin.

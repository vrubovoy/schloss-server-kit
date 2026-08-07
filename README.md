# schloss-server-kit

[![Test](https://github.com/zudaR107/schloss-server-kit/actions/workflows/test.yml/badge.svg)](https://github.com/zudaR107/schloss-server-kit/actions/workflows/test.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

Part of the [Hof platform](https://github.com/zudaR107/Hof) — a suite of
self-hosted personal services:

- [`schloss`](https://github.com/zudaR107/schloss) — home page / launcher
- [`schlussel`](https://github.com/zudaR107/schlussel) — auth: accounts, login, tokens
- [`kuvert`](https://github.com/zudaR107/kuvert) — envelope budgeting
- [`tafel`](https://github.com/zudaR107/tafel) — task/project tracking
- [`zettel`](https://github.com/zudaR107/zettel) — markdown note-taking
- [`tor`](https://github.com/zudaR107/tor) — reverse-proxy gateway
- [`schloss-ui`](https://github.com/zudaR107/schloss-ui) — shared frontend components
- **`schloss-server-kit`** (this repo) — shared backend auth/CORS kit

Shared Hono backend kit consumed by every backend service's API.

Every backend service on the platform verifies JWTs issued by schlüssel
against the same JWKS endpoint, and gates cross-origin requests with the
same origin-allowlist pattern. This package extracts that identical logic
out of each service's own repo into one place, so it's implemented and
tested once instead of copy-pasted per service.

## Not published to any registry

Like `schloss-ui`, this package is consumed by adding it as a git submodule
and depending on it via pnpm's `workspace:*` protocol — not via npm/GitHub
Packages. To use it in a new service:

```sh
git submodule add https://github.com/zudaR107/schloss-server-kit.git schloss-server-kit
```

Add `"schloss-server-kit"` to your `pnpm-workspace.yaml`'s `packages:` list,
and `"@zudar107/schloss-server-kit": "workspace:*"` to your API package's
`package.json`. Build it once before your own app: `pnpm --filter @zudar107/schloss-server-kit build`.

## Usage

```ts
import { createAuthMiddleware, createCorsMiddleware } from '@zudar107/schloss-server-kit'

const { requireAuth, requireAdmin } = createAuthMiddleware({
  jwksUrl: process.env.SCHLUSSEL_JWKS_URL ?? 'http://schlussel:4000/.well-known/jwks.json',
  issuer: process.env.JWT_ISSUER ?? 'schlussel',
  onUserSeen: async (user) => {
    // auto-provision (or touch) a local row keyed by user.id, however
    // your own service's users table is shaped
  },
})

app.use('*', createCorsMiddleware({ allowedOrigins: ALLOWED_ORIGINS }))
app.use('/some-protected-route/*', requireAuth)
app.use('/admin-only-route/*', requireAuth, requireAdmin)
```

After RS256 signature, issuer, and expiry verification, the auth middleware
validates the token's application claims before calling `onUserSeen`. `token_use`
must be `access` when present; signed legacy access tokens without that claim
remain valid during the rollout. `sub`, `email`, and `name` must be nonempty strings; and
`role` must be `user` or `admin`. The optional regional claims are exposed on
`AuthUser` as `weekStart` (`monday`, `sunday`, or `null`), `dateFormat` (`dmy`,
`mdy`, `ymd`, or `null`), and `timezone` (a string containing a valid IANA
timezone identifier, or `null`). Missing regional claims are normalized to
`null`; malformed timezone identifiers reject the token before `onUserSeen`
runs.

The CORS middleware allows `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS`
requests from configured origins.

### Data export contracts

`exportEnvelopeSchema` validates a strict shared versioned wrapper. Its `data`
field must be JSON, but its structure remains service-owned and opaque to this
package.

```ts
import { Hono } from 'hono'
import {
  createExportAuthMiddleware,
  exportEnvelopeSchema,
} from '@zudar107/schloss-server-kit'
import type { ExportAuthEnv } from '@zudar107/schloss-server-kit'

const app = new Hono<ExportAuthEnv>()
const requireExportAuth = createExportAuthMiddleware({
  jwksUrl: process.env.SCHLUSSEL_JWKS_URL ?? 'http://schlussel:4000/.well-known/jwks.json',
  issuer: process.env.JWT_ISSUER ?? 'schlussel',
  service: 'zettel',
})

app.get('/exports/me', requireExportAuth, async (c) => {
  const principal = c.get('exportPrincipal')
  const data = await exportDataForUser(principal.sub)

  return c.json(exportEnvelopeSchema.parse({
    version: '1',
    service: 'zettel',
    exportedAt: new Date().toISOString(),
    data,
  }))
})
```

`createExportAuthMiddleware` accepts either a normal access token with all
claims required by `createAuthMiddleware` (including legacy tokens without
`token_use`), or an export delegation. It stores only a safe `ExportPrincipal`: access tokens produce
`{ sub, kind: 'access' }`; delegations produce
`{ sub, kind: 'delegation', jobId }`. `createExportAuthVerifier` exposes the same
mixed validation without Hono.

Delegations must be JWKS-verified RS256 tokens with the configured exact issuer,
the single exact audience `hof-service:<service>`, `token_use: 'export'`, a
space-delimited scope containing the exact `data:export` entry, nonempty `sub`,
`job_id`, and `jti` claims, and a non-expired numeric `exp`. The delegation-only
`createExportDelegationVerifier` and `createExportDelegationMiddleware` remain
available; the latter uses the explicit `ExportDelegationEnv` Hono type. Export
delegations never pass ordinary `createAuthMiddleware`. These contracts do not
provide export storage or job orchestration.

#### Rollout

Deploy the Schlussel change that emits `token_use: 'access'` before or together
with consumers. Previously issued access tokens remain accepted only when they
still have the complete access-token claim shape and a valid signature and
expiration. Tokens explicitly marked for refresh or export remain invalid on
ordinary routes.

The platform's current fixed signing `kid` makes coordinated JWKS key rotation
existing deployment debt. This feature continues to use the shared remote JWKS
as-is and does not introduce a separate rotation mechanism.

### Notification transport

The notification helpers validate a domain-agnostic v1 event envelope and sign
the exact request body bytes. Consumers provide their own payload schema after
validating the shared envelope.

```ts
import {
  notificationEventEnvelopeSchema,
  signNotificationRequest,
  verifyNotificationRequest,
} from '@zudar107/schloss-server-kit'

const event = notificationEventEnvelopeSchema.parse(await request.json())

const signature = signNotificationRequest({
  secret: process.env.NOTIFICATION_SECRET!,
  keyId: 'schlussel-2026-01',
  source: 'schlussel',
  timestamp: Math.floor(Date.now() / 1_000),
  method: 'POST',
  path: '/internal/v1/events',
  rawBody,
})

const requestUrl = new URL(request.url)
const authentic = verifyNotificationRequest({
  secret: process.env.NOTIFICATION_SECRET!,
  keyId: request.headers.get('X-Hof-Key-Id') ?? '',
  source: request.headers.get('X-Hof-Service') ?? '',
  timestamp: Number(request.headers.get('X-Hof-Timestamp')),
  method: request.method,
  path: `${requestUrl.pathname}${requestUrl.search}`,
  rawBody,
  signature: request.headers.get('X-Hof-Signature') ?? '',
  expectedKeyId: 'schlussel-2026-01',
  expectedSource: 'schlussel',
  maxSkewSeconds: 300,
})
```

`classifyNotificationResponse`, `parseRetryAfter`, and
`calculateBackoffDelay` provide retry policy primitives. Time and randomness
can be injected for deterministic callers and tests.

## Development

```sh
pnpm install
pnpm test
pnpm lint
pnpm typecheck
pnpm build
```

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

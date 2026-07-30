# schloss-server-kit

[![Test](https://github.com/zudaR107/schloss-server-kit/actions/workflows/test.yml/badge.svg)](https://github.com/zudaR107/schloss-server-kit/actions/workflows/test.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

Shared Hono backend kit for the [Schloss Platform](https://github.com/zudaR107/tor) —
part of a self-hosted, open-source personal services ecosystem (schloss,
schlüssel, kuvert, tafel, ...).

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
  onUserSeen: async (claims) => {
    // auto-provision (or touch) a local row keyed by claims.sub, however
    // your own service's users table is shaped
  },
})

app.use('*', createCorsMiddleware({ allowedOrigins: ALLOWED_ORIGINS }))
app.use('/some-protected-route/*', requireAuth)
app.use('/admin-only-route/*', requireAuth, requireAdmin)
```

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

import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import type { JWK } from 'jose'
import { createAuthMiddleware } from './auth.js'
import type { AuthUser } from './auth.js'

const ISSUER = 'schlussel'

async function startJwksServer(jwk: JWK): Promise<{ url: string; server: Server }> {
  const server = createServer((_req, res) => {
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({ keys: [jwk] }))
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (address === null || typeof address === 'string') {
    throw new Error('failed to bind JWKS server')
  }
  return { url: `http://127.0.0.1:${address.port}/jwks.json`, server }
}

describe('createAuthMiddleware', () => {
  let jwksServer: Server
  let jwksUrl: string
  let privateKey: CryptoKey
  let otherPrivateKey: CryptoKey

  const baseUser = {
    sub: 'user-123',
    email: 'alice@example.com',
    name: 'Alice Example',
    role: 'user' as const,
  }

  async function signToken(
    key: CryptoKey,
    overrides: Partial<{
      iss: string
      sub: unknown
      email: unknown
      name: unknown
      role: unknown
      weekStart: unknown
      dateFormat: unknown
      timezone: unknown
      exp: string
      omitClaims: (keyof typeof baseUser)[]
    }> = {},
  ): Promise<string> {
    const { iss = ISSUER, exp = '1h', omitClaims = [], ...claimOverrides } = overrides
    const payload: Record<string, unknown> = { ...baseUser, ...claimOverrides }
    for (const key of omitClaims) delete payload[key]

    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuedAt()
      .setIssuer(iss)
      .setExpirationTime(exp)
      .sign(key)
  }

  beforeAll(async () => {
    const { publicKey, privateKey: pk } = await generateKeyPair('ES256', { extractable: true })
    privateKey = pk
    const jwk = await exportJWK(publicKey)
    jwk.alg = 'ES256'
    jwk.use = 'sig'

    const other = await generateKeyPair('ES256', { extractable: true })
    otherPrivateKey = other.privateKey

    const started = await startJwksServer(jwk)
    jwksServer = started.server
    jwksUrl = started.url
  })

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      jwksServer.close((err) => (err ? reject(err) : resolve()))
    })
  })

  function buildApp(onUserSeen: (user: AuthUser) => Promise<void>) {
    const { requireAuth, requireAdmin } = createAuthMiddleware({
      jwksUrl,
      issuer: ISSUER,
      onUserSeen,
    })

    const app = new Hono<{ Variables: { user: AuthUser } }>()
    app.get('/me', requireAuth, (c) => c.json(c.get('user')))
    app.get('/admin', requireAuth, requireAdmin, (c) => c.json({ ok: true }))
    return app
  }

  describe('requireAuth', () => {
    it('responds 401 Unauthorized when Authorization header is missing', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const res = await app.request('/me')

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Unauthorized' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('responds 401 Unauthorized when Authorization header lacks the Bearer prefix', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const token = await signToken(privateKey)
      const res = await app.request('/me', {
        headers: { Authorization: `Token ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Unauthorized' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('responds 401 Invalid or expired token for a token signed by a key not in the JWKS', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const token = await signToken(otherPrivateKey)
      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('responds 401 Invalid or expired token when the issuer claim does not match', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const token = await signToken(privateKey, { iss: 'someone-else' })
      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('responds 401 Invalid or expired token for an expired token', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const token = await signToken(privateKey, { exp: '-1h' })
      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('responds 401 Invalid or expired token for a malformed token', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const res = await app.request('/me', {
        headers: { Authorization: 'Bearer not-a-jwt' },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it.each(['sub', 'email', 'name', 'role'] as const)(
      'rejects a signed token missing the required %s identity claim',
      async (claim) => {
        const onUserSeen = vi.fn(async () => {})
        const app = buildApp(onUserSeen)
        const token = await signToken(privateKey, { omitClaims: [claim] })

        const res = await app.request('/me', {
          headers: { Authorization: `Bearer ${token}` },
        })

        expect(res.status).toBe(401)
        expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
        expect(onUserSeen).not.toHaveBeenCalled()
      },
    )

    it.each([
      ['sub', ''],
      ['email', 42],
      ['name', { first: 'Alice' }],
      ['role', 'owner'],
    ] as const)('rejects a signed token with a malformed %s identity claim', async (claim, value) => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, { [claim]: value })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it.each([
      ['weekStart', 'friday'],
      ['dateFormat', 'iso'],
      ['timezone', 42],
    ] as const)('rejects a signed token with a malformed optional %s claim', async (claim, value) => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, { [claim]: value })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('passes valid optional regional claims to onUserSeen and downstream handlers', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, {
        weekStart: 'sunday',
        dateFormat: 'ymd',
        timezone: 'Europe/Moscow',
      })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      const expectedUser: AuthUser = {
        id: baseUser.sub,
        email: baseUser.email,
        name: baseUser.name,
        role: baseUser.role,
        weekStart: 'sunday',
        dateFormat: 'ymd',
        timezone: 'Europe/Moscow',
      }
      expect(res.status).toBe(200)
      expect(await res.json()).toEqual(expectedUser)
      expect(onUserSeen).toHaveBeenCalledWith(expectedUser)
    })

    it('lets an onUserSeen provisioning error reach the application error handler', async () => {
      const onUserSeen = vi.fn(async () => {
        throw new Error('database unavailable')
      })
      const app = buildApp(onUserSeen)
      app.onError((error, c) => c.json({ error: error.message }, 503))
      const token = await signToken(privateKey)

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(503)
      expect(await res.json()).toEqual({ error: 'database unavailable' })
      expect(onUserSeen).toHaveBeenCalledTimes(1)
    })

    it('on a valid token: calls onUserSeen once, sets c.get("user"), and reaches downstream', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const token = await signToken(privateKey, {
        sub: 'user-abc',
        email: 'bob@example.com',
        name: 'Bob Example',
        role: 'user',
      })
      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      const expectedUser: AuthUser = {
        id: 'user-abc',
        email: 'bob@example.com',
        name: 'Bob Example',
        role: 'user',
        weekStart: null,
        dateFormat: null,
        timezone: null,
      }

      expect(res.status).toBe(200)
      expect(await res.json()).toEqual(expectedUser)
      expect(onUserSeen).toHaveBeenCalledTimes(1)
      expect(onUserSeen).toHaveBeenCalledWith(expectedUser)
    })
  })

  describe('requireAdmin', () => {
    it('responds 403 Forbidden and does not reach downstream when role is user', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const token = await signToken(privateKey, { role: 'user' })
      const res = await app.request('/admin', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(403)
      expect(await res.json()).toEqual({ error: 'Forbidden' })
    })

    it('reaches downstream and passes through the response when role is admin', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)

      const token = await signToken(privateKey, { role: 'admin' })
      const res = await app.request('/admin', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(200)
      expect(await res.json()).toEqual({ ok: true })
    })
  })
})

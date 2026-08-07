import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import type { JWK } from 'jose'
import { createAuthMiddleware } from './auth.js'
import type { AuthUser } from './auth.js'

const ISSUER = 'schlussel'

async function startJwksServer(jwks: JWK[]): Promise<{ url: string; server: Server }> {
  const server = createServer((_req, res) => {
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({ keys: jwks }))
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
  let ecPrivateKey: CryptoKey

  const baseUser = {
    sub: 'user-123',
    email: 'alice@example.com',
    name: 'Alice Example',
    role: 'user' as const,
    token_use: 'access' as const,
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
      token_use: unknown
      jti: unknown
      algorithm: 'RS256' | 'ES256'
      exp: string
      omitExpiration: boolean
      omitClaims: readonly (keyof typeof baseUser)[]
    }> = {},
  ): Promise<string> {
    const {
      iss = ISSUER,
      algorithm = 'RS256',
      exp = '1h',
      omitExpiration = false,
      omitClaims = [],
      ...claimOverrides
    } = overrides
    const payload: Record<string, unknown> = { ...baseUser, ...claimOverrides }
    for (const key of omitClaims) delete payload[key]

    let token = new SignJWT(payload)
      .setProtectedHeader({ alg: algorithm })
      .setIssuedAt()
      .setIssuer(iss)
    if (!omitExpiration) token = token.setExpirationTime(exp)
    return token.sign(key)
  }

  beforeAll(async () => {
    const { publicKey, privateKey: pk } = await generateKeyPair('RS256', { extractable: true })
    privateKey = pk
    const jwk = await exportJWK(publicKey)
    jwk.alg = 'RS256'
    jwk.use = 'sig'

    const other = await generateKeyPair('RS256', { extractable: true })
    otherPrivateKey = other.privateKey

    const ec = await generateKeyPair('ES256', { extractable: true })
    ecPrivateKey = ec.privateKey
    const ecJwk = await exportJWK(ec.publicKey)
    ecJwk.alg = 'ES256'
    ecJwk.use = 'sig'

    const started = await startJwksServer([jwk, ecJwk])
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

    it('responds 401 Invalid or expired token for a trusted key using ES256', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(ecPrivateKey, { algorithm: 'ES256' })

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

    it('responds 401 Invalid or expired token without an expiration claim', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, { omitExpiration: true })

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

    it('rejects an explicit non-access token-use discriminator', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, { token_use: 'export' })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('rejects a signed, unexpired claimless token without a token-use discriminator', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, {
        omitClaims: ['sub', 'email', 'name', 'role', 'token_use'],
      })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('rejects an undiscriminated refresh-shaped token without access identity claims', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, {
        jti: 'refresh-123',
        omitClaims: ['email', 'name', 'role', 'token_use'],
      })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

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

    it('rejects a signed token with a timezone that is not a valid IANA identifier', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, { timezone: 'Mars/Olympus_Mons' })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Invalid or expired token' })
      expect(onUserSeen).not.toHaveBeenCalled()
    })

    it('allows an explicitly null timezone claim', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, { timezone: null })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(res.status).toBe(200)
      expect(await res.json()).toMatchObject({ timezone: null })
      expect(onUserSeen).toHaveBeenCalledWith(expect.objectContaining({ timezone: null }))
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

    it('accepts a signed, unexpired legacy access-shaped token without token_use', async () => {
      const onUserSeen = vi.fn(async () => {})
      const app = buildApp(onUserSeen)
      const token = await signToken(privateKey, { omitClaims: ['token_use'] })

      const res = await app.request('/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      const expectedUser: AuthUser = {
        id: baseUser.sub,
        email: baseUser.email,
        name: baseUser.name,
        role: baseUser.role,
        weekStart: null,
        dateFormat: null,
        timezone: null,
      }
      expect(res.status).toBe(200)
      expect(await res.json()).toEqual(expectedUser)
      expect(onUserSeen).toHaveBeenCalledOnce()
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

    it('prefers an explicit access token use and reaches downstream with the user', async () => {
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

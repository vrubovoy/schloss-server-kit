import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import type { JWK } from 'jose'
import { createAuthMiddleware } from './auth.js'
import {
  createExportAuthMiddleware,
  createExportAuthVerifier,
  createExportDelegationMiddleware,
  createExportDelegationVerifier,
  exportEnvelopeSchema,
} from './export.js'
import type { ExportAuthEnv, ExportDelegationEnv } from './export.js'

const ISSUER = 'schlussel'
const SERVICE = 'zettel'
const AUDIENCE = `hof-service:${SERVICE}`

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

describe('export envelope', () => {
  const validEnvelope = {
    version: '1',
    service: SERVICE,
    exportedAt: '2026-08-07T12:00:00.000Z',
    data: {
      notes: [{ id: 'note-123', title: 'Packing list' }],
      tags: [],
    },
  }

  it('accepts a stable version 1 envelope without depending on a service data schema', () => {
    expect(exportEnvelopeSchema.parse(validEnvelope)).toEqual(validEnvelope)
  })

  it.each([
    ['an unsupported version', { version: '2' }],
    ['an empty service name', { service: '' }],
    ['a malformed export timestamp', { exportedAt: '7 August 2026' }],
  ])('rejects %s', (_description, override) => {
    expect(exportEnvelopeSchema.safeParse({ ...validEnvelope, ...override }).success).toBe(false)
  })

  it('requires the service-owned data field even though its contents are opaque', () => {
    const { data: _data, ...withoutData } = validEnvelope

    expect(exportEnvelopeSchema.safeParse(withoutData).success).toBe(false)
  })

  it('rejects unknown envelope fields', () => {
    expect(exportEnvelopeSchema.safeParse({ ...validEnvelope, checksum: 'abc123' }).success).toBe(false)
  })

  it.each([undefined, 1n, new Date()])('rejects non-JSON data: %s', (data) => {
    expect(exportEnvelopeSchema.safeParse({ ...validEnvelope, data }).success).toBe(false)
  })
})

describe('export delegation', () => {
  let jwksServer: Server
  let jwksUrl: string
  let rsaPrivateKey: CryptoKey
  let ecPrivateKey: CryptoKey

  type TokenOptions = {
    algorithm?: 'RS256' | 'ES256'
    issuer?: string
    audience?: string | string[]
    omitAudience?: boolean
    expiration?: string
    omitExpiration?: boolean
    omitClaims?: Array<'sub' | 'job_id' | 'jti' | 'token_use' | 'scope' | 'email' | 'name' | 'role'>
    claims?: Record<string, unknown>
  }

  async function signDelegation(options: TokenOptions = {}): Promise<string> {
    const {
      algorithm = 'RS256',
      issuer = ISSUER,
      audience = AUDIENCE,
      omitAudience = false,
      expiration = '5m',
      omitExpiration = false,
      omitClaims = [],
      claims = {},
    } = options
    const payload: Record<string, unknown> = {
      sub: 'user-123',
      job_id: 'job-123',
      jti: 'delegation-123',
      token_use: 'export',
      scope: 'openid data:export audit',
      // A delegation must still be rejected by ordinary auth even if it carries
      // every identity claim that would otherwise make an access token valid.
      email: 'alice@example.com',
      name: 'Alice Example',
      role: 'user',
      ...claims,
    }
    for (const claim of omitClaims) delete payload[claim]

    let token = new SignJWT(payload)
      .setProtectedHeader({ alg: algorithm, kid: algorithm === 'RS256' ? 'rsa-1' : 'ec-1' })
      .setIssuedAt()
      .setIssuer(issuer)
    if (!omitAudience) token = token.setAudience(audience)
    if (!omitExpiration) token = token.setExpirationTime(expiration)

    return token.sign(algorithm === 'RS256' ? rsaPrivateKey : ecPrivateKey)
  }

  async function signAccessToken(
    claims: Record<string, unknown> = {},
    omitClaims: readonly string[] = [],
  ): Promise<string> {
    const payload: Record<string, unknown> = {
      sub: 'user-123',
      email: 'alice@example.com',
      name: 'Alice Example',
      role: 'user',
      token_use: 'access',
      ...claims,
    }
    for (const claim of omitClaims) delete payload[claim]

    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: 'rsa-1' })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setExpirationTime('1h')
      .sign(rsaPrivateKey)
  }

  beforeAll(async () => {
    const rsa = await generateKeyPair('RS256', { extractable: true })
    rsaPrivateKey = rsa.privateKey
    const rsaJwk = await exportJWK(rsa.publicKey)
    rsaJwk.alg = 'RS256'
    rsaJwk.use = 'sig'
    rsaJwk.kid = 'rsa-1'

    const ec = await generateKeyPair('ES256', { extractable: true })
    ecPrivateKey = ec.privateKey
    const ecJwk = await exportJWK(ec.publicKey)
    ecJwk.alg = 'ES256'
    ecJwk.use = 'sig'
    ecJwk.kid = 'ec-1'

    const started = await startJwksServer([rsaJwk, ecJwk])
    jwksServer = started.server
    jwksUrl = started.url
  })

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      jwksServer.close((error) => (error ? reject(error) : resolve()))
    })
  })

  function verifier() {
    return createExportDelegationVerifier({ jwksUrl, issuer: ISSUER, service: SERVICE })
  }

  it('verifies a Schlussel RS256 delegation from JWKS for the exact service audience and export scope', async () => {
    const token = await signDelegation()

    await expect(verifier()(token)).resolves.toEqual({
      sub: 'user-123',
      job_id: 'job-123',
      jti: 'delegation-123',
      exp: expect.any(Number),
    })
  })

  it.each([
    ['no audience', { omitAudience: true }],
    ['another service audience', { audience: 'hof-service:kuvert' }],
    ['a broader audience', { audience: ['hof-service:kuvert', AUDIENCE] }],
    ['a scope without export permission', { claims: { scope: 'openid profile audit' } }],
    ['a lookalike scope', { claims: { scope: 'openid data:export:all audit' } }],
    ['an array-valued scope', { claims: { scope: ['data:export'] } }],
    ['another token use', { claims: { token_use: 'access' } }],
    ['another issuer', { issuer: 'attacker' }],
    ['an expired token', { expiration: '-1s' }],
    ['a trusted key using ES256', { algorithm: 'ES256' }],
  ] satisfies Array<[string, TokenOptions]>)('rejects %s', async (_description, options) => {
    const token = await signDelegation(options)

    await expect(verifier()(token)).rejects.toThrow()
  })

  it.each(['sub', 'job_id', 'jti', 'token_use', 'scope'] as const)(
    'rejects a signed delegation missing the required %s claim',
    async (claim) => {
      const token = await signDelegation({ omitClaims: [claim] })

      await expect(verifier()(token)).rejects.toThrow()
    },
  )

  it.each([
    ['sub', ''],
    ['job_id', 42],
    ['jti', ''],
  ] as const)('rejects a signed delegation with a malformed %s claim', async (claim, value) => {
    const token = await signDelegation({ claims: { [claim]: value } })

    await expect(verifier()(token)).rejects.toThrow()
  })

  it('rejects a signed delegation without an expiration claim', async () => {
    const token = await signDelegation({ omitExpiration: true })

    await expect(verifier()(token)).rejects.toThrow()
  })

  it('rejects a signed delegation with a non-numeric expiration claim', async () => {
    const token = await signDelegation({ omitExpiration: true, claims: { exp: 'tomorrow' } })

    await expect(verifier()(token)).rejects.toThrow()
  })

  it('does not treat a normal Schlussel access token as export delegation', async () => {
    const token = await signAccessToken()

    await expect(verifier()(token)).rejects.toThrow()
  })

  describe('createExportDelegationMiddleware', () => {
    function buildApp() {
      const requireExportDelegation = createExportDelegationMiddleware({
        jwksUrl,
        issuer: ISSUER,
        service: SERVICE,
      })
      const app = new Hono<ExportDelegationEnv>()
      app.get('/exports/me', requireExportDelegation, (c) => c.json(c.get('exportDelegation')))
      return app
    }

    it('sets the validated delegation claims and reaches downstream', async () => {
      const app = buildApp()
      const token = await signDelegation()

      const response = await app.request('/exports/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual({
        sub: 'user-123',
        job_id: 'job-123',
        jti: 'delegation-123',
        exp: expect.any(Number),
      })
    })

    it('responds 401 Unauthorized when the Bearer token is missing', async () => {
      const response = await buildApp().request('/exports/me')

      expect(response.status).toBe(401)
      expect(await response.json()).toEqual({ error: 'Unauthorized' })
    })

    it('responds 401 Invalid or expired token for an invalid delegation', async () => {
      const token = await signDelegation({ audience: 'hof-service:kuvert' })
      const response = await buildApp().request('/exports/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(response.status).toBe(401)
      expect(await response.json()).toEqual({ error: 'Invalid or expired token' })
    })
  })

  describe('mixed export auth', () => {
    function verifier() {
      return createExportAuthVerifier({ jwksUrl, issuer: ISSUER, service: SERVICE })
    }

    function buildApp() {
      const requireExportAuth = createExportAuthMiddleware({
        jwksUrl,
        issuer: ISSUER,
        service: SERVICE,
      })
      const app = new Hono<ExportAuthEnv>()
      app.get('/exports/me', requireExportAuth, (c) => c.json(c.get('exportPrincipal')))
      return app
    }

    it('prefers an explicit access token use and returns a minimal access principal', async () => {
      const token = await signAccessToken()

      await expect(verifier()(token)).resolves.toEqual({
        sub: 'user-123',
        kind: 'access',
      })
    })

    it('returns a minimal access principal for a signed, unexpired legacy access-shaped token without token_use', async () => {
      const token = await signAccessToken({}, ['token_use'])

      await expect(verifier()(token)).resolves.toEqual({
        sub: 'user-123',
        kind: 'access',
      })
    })

    it('returns a minimal delegation principal for an exact service delegation', async () => {
      const token = await signDelegation()

      await expect(verifier()(token)).resolves.toEqual({
        sub: 'user-123',
        kind: 'delegation',
        jobId: 'job-123',
      })
    })

    it.each([
      ['an access token with malformed access claims', () => signAccessToken({ role: 'owner' })],
      ['an access token with malformed preferences', () => signAccessToken({ timezone: 42 })],
      ['an access-shaped token explicitly marked for export', () => signAccessToken({ token_use: 'export' })],
      [
        'a signed, unexpired claimless token without a token-use discriminator',
        () => signAccessToken({}, ['sub', 'email', 'name', 'role', 'token_use']),
      ],
      [
        'an undiscriminated refresh-shaped token without access identity claims',
        () => signAccessToken({ jti: 'refresh-123' }, ['email', 'name', 'role', 'token_use']),
      ],
      [
        'an undiscriminated delegation-shaped token without access identity claims',
        () => signDelegation({ omitClaims: ['token_use', 'email', 'name', 'role'] }),
      ],
      ['a delegation for another service', () => signDelegation({ audience: 'hof-service:kuvert' })],
      ['a delegation without the exact scope', () => signDelegation({ claims: { scope: 'data:export:all' } })],
    ] as const)('rejects %s', async (_description, createToken) => {
      const token = await createToken()

      await expect(verifier()(token)).rejects.toThrow()
    })

    it.each([
      ['normal access', () => signAccessToken(), { sub: 'user-123', kind: 'access' }],
      [
        'legacy access without token_use',
        () => signAccessToken({}, ['token_use']),
        { sub: 'user-123', kind: 'access' },
      ],
      [
        'service delegation',
        () => signDelegation(),
        { sub: 'user-123', kind: 'delegation', jobId: 'job-123' },
      ],
    ] as const)('allows %s through /exports/me', async (_description, createToken, principal) => {
      const token = await createToken()
      const response = await buildApp().request('/exports/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual(principal)
    })

    it('responds 401 without a Bearer token', async () => {
      const response = await buildApp().request('/exports/me')

      expect(response.status).toBe(401)
      expect(await response.json()).toEqual({ error: 'Unauthorized' })
    })

    it('responds 401 for a token that is validly signed but invalid for export auth', async () => {
      const token = await signDelegation({ audience: 'hof-service:kuvert' })
      const response = await buildApp().request('/exports/me', {
        headers: { Authorization: `Bearer ${token}` },
      })

      expect(response.status).toBe(401)
      expect(await response.json()).toEqual({ error: 'Invalid or expired token' })
    })
  })

  it('does not allow export delegation through ordinary createAuthMiddleware', async () => {
    const onUserSeen = vi.fn(async () => {})
    const { requireAuth } = createAuthMiddleware({ jwksUrl, issuer: ISSUER, onUserSeen })
    const app = new Hono()
    app.get('/ordinary', requireAuth, (c) => c.json({ ok: true }))
    const token = await signDelegation()

    const response = await app.request('/ordinary', {
      headers: { Authorization: `Bearer ${token}` },
    })

    expect(response.status).toBe(401)
    expect(onUserSeen).not.toHaveBeenCalled()
  })
})

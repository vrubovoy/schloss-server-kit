import { createMiddleware } from 'hono/factory'
import type { MiddlewareHandler } from 'hono'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import type { JWTPayload } from 'jose'
import { z } from 'zod'
import { userFromAccessPayload } from './auth.js'

export const exportEnvelopeSchema = z
  .object({
    version: z.literal('1'),
    service: z.string().min(1),
    exportedAt: z.iso.datetime(),
    data: z.json(),
  })
  .strict()

export type ExportEnvelope = z.infer<typeof exportEnvelopeSchema>

export interface ExportDelegation {
  sub: string
  job_id: string
  jti: string
  exp: number
}

export interface CreateExportDelegationVerifierConfig {
  jwksUrl: string
  issuer: string
  service: string
}

export type ExportDelegationVerifier = (token: string) => Promise<ExportDelegation>

export type ExportDelegationEnv = {
  Variables: {
    exportDelegation: ExportDelegation
  }
}

export type ExportPrincipal =
  | { sub: string; kind: 'access' }
  | { sub: string; kind: 'delegation'; jobId: string }

export type ExportAuthEnv = {
  Variables: {
    exportPrincipal: ExportPrincipal
  }
}

export type CreateExportAuthVerifierConfig = CreateExportDelegationVerifierConfig

export type ExportAuthVerifier = (token: string) => Promise<ExportPrincipal>

function delegationFromPayload(payload: JWTPayload, audience: string): ExportDelegation {
  const { sub, aud, job_id, jti, exp, token_use, scope } = payload

  if (
    typeof sub !== 'string' ||
    sub.length === 0 ||
    aud !== audience ||
    typeof job_id !== 'string' ||
    job_id.length === 0 ||
    typeof jti !== 'string' ||
    jti.length === 0 ||
    typeof exp !== 'number' ||
    !Number.isFinite(exp) ||
    token_use !== 'export' ||
    typeof scope !== 'string' ||
    !scope.split(/\s+/).includes('data:export')
  ) {
    throw new Error('Invalid export delegation claims')
  }

  return { sub, job_id, jti, exp }
}

export function createExportDelegationVerifier(
  config: CreateExportDelegationVerifierConfig,
): ExportDelegationVerifier {
  const jwks = createRemoteJWKSet(new URL(config.jwksUrl))
  const audience = `hof-service:${config.service}`

  return async (token) => {
    const { payload } = await jwtVerify(token, jwks, {
      algorithms: ['RS256'],
      issuer: config.issuer,
      audience,
    })
    return delegationFromPayload(payload, audience)
  }
}

export function createExportDelegationMiddleware(
  config: CreateExportDelegationVerifierConfig,
): MiddlewareHandler<ExportDelegationEnv> {
  const verify = createExportDelegationVerifier(config)

  return createMiddleware<ExportDelegationEnv>(async (c, next) => {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized' }, 401)
    }

    let delegation: ExportDelegation
    try {
      delegation = await verify(authHeader.slice(7))
    } catch {
      return c.json({ error: 'Invalid or expired token' }, 401)
    }

    c.set('exportDelegation', delegation)
    await next()
  })
}

export function createExportAuthVerifier(config: CreateExportAuthVerifierConfig): ExportAuthVerifier {
  const jwks = createRemoteJWKSet(new URL(config.jwksUrl))
  const audience = `hof-service:${config.service}`

  return async (token) => {
    const { payload } = await jwtVerify(token, jwks, {
      algorithms: ['RS256'],
      issuer: config.issuer,
      requiredClaims: ['exp'],
    })

    if (payload['token_use'] === undefined || payload['token_use'] === 'access') {
      const user = userFromAccessPayload(payload)
      return { sub: user.id, kind: 'access' }
    }

    const delegation = delegationFromPayload(payload, audience)
    return { sub: delegation.sub, kind: 'delegation', jobId: delegation.job_id }
  }
}

export function createExportAuthMiddleware(
  config: CreateExportAuthVerifierConfig,
): MiddlewareHandler<ExportAuthEnv> {
  const verify = createExportAuthVerifier(config)

  return createMiddleware<ExportAuthEnv>(async (c, next) => {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized' }, 401)
    }

    let principal: ExportPrincipal
    try {
      principal = await verify(authHeader.slice(7))
    } catch {
      return c.json({ error: 'Invalid or expired token' }, 401)
    }

    c.set('exportPrincipal', principal)
    await next()
  })
}

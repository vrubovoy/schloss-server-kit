import { createMiddleware } from 'hono/factory'
import type { MiddlewareHandler } from 'hono'
import { jwtVerify, createRemoteJWKSet } from 'jose'

export interface AuthUser {
  id: string
  email: string
  name: string
  role: 'admin' | 'user'
  // Schlüssel-owned profile prefs, embedded directly in the token claim
  // (see schlussel's own JwtPayload) so a consuming service can actually
  // render with them - a real IANA week-start/date-format/timezone
  // choice, not a value only schlussel itself ever reads. Null when the
  // user has never set that preference; a consuming service's own
  // rendering code decides its own display default in that case, exactly
  // like schlussel's account page does.
  weekStart: 'monday' | 'sunday' | null
  dateFormat: 'dmy' | 'mdy' | 'ymd' | null
  timezone: string | null
}

declare module 'hono' {
  interface ContextVariableMap {
    user: AuthUser
  }
}

export interface CreateAuthMiddlewareConfig {
  jwksUrl: string
  issuer: string
  // Each consuming service owns its own `users` table shape (kuvert has a
  // `currency` column, others won't) - this callback is how a service
  // auto-provisions/touches its own local row on first sight of a user,
  // without this package assuming any particular schema.
  onUserSeen: (user: AuthUser) => Promise<void>
}

export interface AuthMiddlewares {
  requireAuth: MiddlewareHandler
  requireAdmin: MiddlewareHandler
}

export function createAuthMiddleware(config: CreateAuthMiddlewareConfig): AuthMiddlewares {
  const { jwksUrl, issuer, onUserSeen } = config
  const jwks = createRemoteJWKSet(new URL(jwksUrl))

  const requireAuth = createMiddleware(async (c, next) => {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized' }, 401)
    }

    try {
      const { payload } = await jwtVerify(authHeader.slice(7), jwks, { issuer })

      const user: AuthUser = {
        id: payload.sub as string,
        email: payload['email'] as string,
        name: payload['name'] as string,
        role: payload['role'] as 'admin' | 'user',
        weekStart: (payload['weekStart'] as 'monday' | 'sunday' | null | undefined) ?? null,
        dateFormat: (payload['dateFormat'] as 'dmy' | 'mdy' | 'ymd' | null | undefined) ?? null,
        timezone: (payload['timezone'] as string | null | undefined) ?? null,
      }

      await onUserSeen(user)

      c.set('user', user)
      await next()
    } catch {
      return c.json({ error: 'Invalid or expired token' }, 401)
    }
  })

  // Composed after requireAuth (which already verified the JWT and set
  // `c.get('user')`) - just reads the role that's already there, since
  // schlussel embeds it directly in the token claim.
  const requireAdmin = createMiddleware(async (c, next) => {
    const user = c.get('user')
    if (user.role !== 'admin') {
      return c.json({ error: 'Forbidden' }, 403)
    }
    await next()
  })

  return { requireAuth, requireAdmin }
}

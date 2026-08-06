import { cors } from 'hono/cors'
import type { MiddlewareHandler } from 'hono'

export interface CreateCorsMiddlewareConfig {
  allowedOrigins: string[]
}

export function createCorsMiddleware(config: CreateCorsMiddlewareConfig): MiddlewareHandler {
  const { allowedOrigins } = config
  return cors({
    origin: (origin) => (allowedOrigins.includes(origin) ? origin : null),
    allowHeaders: ['Content-Type', 'Authorization'],
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    credentials: true,
    maxAge: 86400,
  })
}

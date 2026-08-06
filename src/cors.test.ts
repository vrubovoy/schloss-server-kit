import { describe, expect, it } from 'vitest'
import { Hono } from 'hono'
import { createCorsMiddleware } from './cors.js'

const ALLOWED_ORIGIN = 'https://app.example.com'
const OTHER_ORIGIN = 'https://evil.example.com'

function buildApp() {
  const app = new Hono()
  app.use('*', createCorsMiddleware({ allowedOrigins: [ALLOWED_ORIGIN] }))
  app.get('/ping', (c) => c.json({ ok: true }))
  app.post('/ping', (c) => c.json({ ok: true }))
  app.patch('/ping', (c) => c.json({ ok: true }))
  return app
}

describe('createCorsMiddleware', () => {
  it('echoes back an allowed origin and marks credentials allowed', async () => {
    const app = buildApp()

    const res = await app.request('/ping', {
      headers: { Origin: ALLOWED_ORIGIN },
    })

    expect(res.status).toBe(200)
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe(ALLOWED_ORIGIN)
    expect(res.headers.get('Access-Control-Allow-Credentials')).toBe('true')
  })

  it('does not grant CORS for a disallowed origin', async () => {
    const app = buildApp()

    const res = await app.request('/ping', {
      headers: { Origin: OTHER_ORIGIN },
    })

    expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe(OTHER_ORIGIN)
  })

  it('responds to a preflight OPTIONS request from an allowed origin with the expected headers', async () => {
    const app = buildApp()

    const res = await app.request('/ping', {
      method: 'OPTIONS',
      headers: {
        Origin: ALLOWED_ORIGIN,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type, Authorization',
      },
    })

    const allowMethods = res.headers.get('Access-Control-Allow-Methods') ?? ''
    const allowHeaders = res.headers.get('Access-Control-Allow-Headers') ?? ''

    for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']) {
      expect(allowMethods).toContain(method)
    }
    for (const header of ['Content-Type', 'Authorization']) {
      expect(allowHeaders.toLowerCase()).toContain(header.toLowerCase())
    }
    expect(res.headers.get('Access-Control-Max-Age')).toBe('86400')
  })

  it('allows PATCH in a preflight request from an allowed origin', async () => {
    const app = buildApp()

    const res = await app.request('/ping', {
      method: 'OPTIONS',
      headers: {
        Origin: ALLOWED_ORIGIN,
        'Access-Control-Request-Method': 'PATCH',
      },
    })

    expect(res.status).toBe(204)
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe(ALLOWED_ORIGIN)
    expect(res.headers.get('Access-Control-Allow-Methods')).toContain('PATCH')
  })

  it('lets a request with no Origin header reach the downstream handler normally', async () => {
    const app = buildApp()

    const res = await app.request('/ping')

    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
  })

  it('lets a request from an allowed origin reach the downstream handler normally', async () => {
    const app = buildApp()

    const res = await app.request('/ping', {
      headers: { Origin: ALLOWED_ORIGIN },
    })

    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
  })
})

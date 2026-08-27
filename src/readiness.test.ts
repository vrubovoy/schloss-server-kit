import { createServer } from 'node:http'
import type { RequestListener, Server } from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'
import { checkJwksReachable } from './readiness.js'

async function startServer(handler: RequestListener): Promise<{ url: string; server: Server }> {
  const server = createServer(handler)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('failed to bind test server')
  return { url: `http://127.0.0.1:${address.port}/`, server }
}

describe('checkJwksReachable', () => {
  let server: Server | undefined

  afterEach(async () => {
    if (server) await new Promise<void>((resolve) => server!.close(() => resolve()))
    server = undefined
  })

  it('returns true when the JWKS endpoint responds ok', async () => {
    const started = await startServer((_req, res) => res.end('{"keys":[]}'))
    server = started.server

    await expect(checkJwksReachable(started.url)).resolves.toBe(true)
  })

  it('returns false when the JWKS endpoint responds with an error status', async () => {
    const started = await startServer((_req, res) => {
      res.statusCode = 503
      res.end('unavailable')
    })
    server = started.server

    await expect(checkJwksReachable(started.url)).resolves.toBe(false)
  })

  it('returns false when the request cannot connect at all', async () => {
    await expect(checkJwksReachable('http://127.0.0.1:1')).resolves.toBe(false)
  })

  it('returns false and does not hang past the timeout when the server never responds', async () => {
    const started = await startServer(() => {
      // Never call res.end() - simulates a hung/unreachable dependency.
    })
    server = started.server

    const start = Date.now()
    await expect(checkJwksReachable(started.url, { timeoutMs: 50 })).resolves.toBe(false)
    expect(Date.now() - start).toBeLessThan(1000)
  })
})

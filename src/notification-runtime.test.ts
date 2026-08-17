import { afterEach, describe, expect, it, vi } from 'vitest'
import { createNotificationOutboxRuntime } from './index.js'
import { signNotificationRequest } from './notification.js'

const NOW_MS = Date.parse('2026-08-07T12:00:00.000Z')
const EVENT_ID = 'f47ac10b-58cc-4372-a567-0e02b2c3d479'
const CORRELATION_ID = '987fcdeb-51a2-43d7-b654-123456789abc'
const SECRET = 'test-secret-that-is-at-least-32-bytes'
const MAX_TIMER_MS = 2_147_483_647
const MAX_DATE_MS = 8_640_000_000_000_000

const row = {
  id: EVENT_ID,
  type: 'reminder.due',
  occurredAt: '2026-08-07T11:59:00.000Z',
  correlationId: CORRELATION_ID,
  payload: { reminderId: 'reminder-123', minutesBefore: 15 },
  attempts: 0,
  leaseToken: 'lease-123',
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

function setup(overrides: Record<string, unknown> = {}) {
  const claim = vi.fn(async () => row)
  const markDelivered = vi.fn(async () => true)
  const markRetry = vi.fn(async () => true)
  const markPermanent = vi.fn(async () => true)
  const fetch = vi.fn(async (_url: string, _init: RequestInit) => new Response(null, { status: 204 }))
  const runtime = createNotificationOutboxRuntime({
    source: 'kalender',
    keyId: 'key-2026-01',
    secret: SECRET,
    baseUrl: 'https://notifications.example/service/',
    claim,
    markDelivered,
    markRetry,
    markPermanent,
    fetch,
    now: () => NOW_MS,
    random: () => 0.5,
    leaseDurationMs: 30_000,
    requestTimeoutMs: 5_000,
    pollIntervalMs: 1_000,
    stopTimeoutMs: 2_000,
    maxAttempts: 5,
    baseDelayMs: 1_000,
    maxDelayMs: 30_000,
    ...overrides,
  })

  return { runtime, claim, markDelivered, markRetry, markPermanent, fetch }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('notification outbox delivery', () => {
  it('claims one row and posts a validated v1 envelope signed over its exact serialized bytes', async () => {
    const { runtime, claim, markDelivered, fetch } = setup()

    await expect(runtime.deliverOne()).resolves.toBe('delivered')

    expect(claim).toHaveBeenCalledOnce()
    expect(claim).toHaveBeenCalledWith({
      now: new Date(NOW_MS),
      leaseUntil: new Date(NOW_MS + 30_000),
    })
    expect(fetch).toHaveBeenCalledOnce()
    const [url, init] = fetch.mock.calls[0]!
    const rawBody = JSON.stringify({
      version: '1',
      id: EVENT_ID,
      type: 'reminder.due',
      source: 'kalender',
      occurredAt: '2026-08-07T11:59:00.000Z',
      correlationId: CORRELATION_ID,
      payload: { reminderId: 'reminder-123', minutesBefore: 15 },
    })
    const timestamp = Math.floor(NOW_MS / 1_000)

    expect(url).toBe('https://notifications.example/internal/v1/events')
    expect(init).toMatchObject({ method: 'POST', body: rawBody })
    expect(init.headers).toEqual({
      'Content-Type': 'application/json',
      'X-Hof-Key-Id': 'key-2026-01',
      'X-Hof-Service': 'kalender',
      'X-Hof-Timestamp': String(timestamp),
      'X-Hof-Signature': signNotificationRequest({
        secret: SECRET,
        keyId: 'key-2026-01',
        source: 'kalender',
        timestamp,
        method: 'POST',
        path: '/internal/v1/events',
        rawBody,
      }),
    })
    expect(markDelivered).toHaveBeenCalledWith({
      id: EVENT_ID,
      leaseToken: 'lease-123',
      deliveredAt: new Date(NOW_MS),
    })
  })

  it.each([200, 201, 202, 204, 299])('treats HTTP %i as delivered', async (status) => {
    const fetch = vi.fn(async () => new Response(null, { status }))
    const { runtime, markDelivered, markRetry, markPermanent } = setup({ fetch })

    await expect(runtime.deliverOne()).resolves.toBe('delivered')

    expect(markDelivered).toHaveBeenCalledOnce()
    expect(markRetry).not.toHaveBeenCalled()
    expect(markPermanent).not.toHaveBeenCalled()
  })

  it('honors Retry-After for a retryable response and keeps the update lease-fenced', async () => {
    const fetch = vi.fn(
      async () => new Response(null, { status: 429, headers: { 'Retry-After': '10' } }),
    )
    const { runtime, markRetry } = setup({ fetch })

    await expect(runtime.deliverOne()).resolves.toBe('retry')

    expect(markRetry).toHaveBeenCalledWith({
      id: EVENT_ID,
      leaseToken: 'lease-123',
      attempts: 1,
      nextAttemptAt: new Date(NOW_MS + 10_000),
      error: 'notification endpoint returned HTTP 429',
    })
  })

  it.each([408, 425, 500, 503, 599])('applies deterministic full jitter after HTTP %i', async (status) => {
    const fetch = vi.fn(async () => new Response(null, { status }))
    const { runtime, markRetry } = setup({ fetch })

    await runtime.deliverOne()

    expect(markRetry).toHaveBeenCalledWith(
      expect.objectContaining({
        attempts: 1,
        nextAttemptAt: new Date(NOW_MS + 500),
      }),
    )
  })

  it.each([400, 401, 403, 404, 409, 422])('permanently fails HTTP %i without retrying', async (status) => {
    const fetch = vi.fn(async () => new Response('private upstream details', { status }))
    const { runtime, markRetry, markPermanent } = setup({ fetch })

    await expect(runtime.deliverOne()).resolves.toBe('permanent')

    expect(markRetry).not.toHaveBeenCalled()
    expect(markPermanent).toHaveBeenCalledWith({
      id: EVENT_ID,
      leaseToken: 'lease-123',
      attempts: 1,
      error: `notification endpoint returned HTTP ${status}`,
    })
    expect(JSON.stringify(markPermanent.mock.calls)).not.toContain('private upstream details')
  })

  it('permanently fails a retryable result when the bounded attempt count is exhausted', async () => {
    const fetch = vi.fn(async () => new Response(null, { status: 503 }))
    const claim = vi.fn(async () => ({ ...row, attempts: 4 }))
    const { runtime, markRetry, markPermanent } = setup({ fetch, claim, maxAttempts: 5 })

    await expect(runtime.deliverOne()).resolves.toBe('permanent')

    expect(markRetry).not.toHaveBeenCalled()
    expect(markPermanent).toHaveBeenCalledWith({
      id: EVENT_ID,
      leaseToken: 'lease-123',
      attempts: 5,
      error: 'notification endpoint returned HTTP 503; maximum attempts reached',
    })
  })

  it('marks an unserializable row permanent without making a request or leaking row data', async () => {
    const claim = vi.fn(async () => ({ ...row, payload: { secretValue: 1n } }))
    const { runtime, fetch, markPermanent } = setup({ claim })

    await expect(runtime.deliverOne()).resolves.toBe('permanent')

    expect(fetch).not.toHaveBeenCalled()
    expect(markPermanent).toHaveBeenCalledWith({
      id: EVENT_ID,
      leaseToken: 'lease-123',
      attempts: 1,
      error: 'invalid notification outbox row',
    })
    expect(JSON.stringify(markPermanent.mock.calls)).not.toContain('secretValue')
  })

  it('returns idle without an update when storage has no eligible row', async () => {
    const claim = vi.fn(async () => null)
    const { runtime, fetch, markDelivered, markRetry, markPermanent } = setup({ claim })

    await expect(runtime.deliverOne()).resolves.toBe('idle')

    expect(fetch).not.toHaveBeenCalled()
    expect(markDelivered).not.toHaveBeenCalled()
    expect(markRetry).not.toHaveBeenCalled()
    expect(markPermanent).not.toHaveBeenCalled()
  })

  it('requires the request timeout to be shorter than the lease', () => {
    expect(() => setup({ leaseDurationMs: 5_000, requestTimeoutMs: 5_000 })).toThrow(
      /request timeout.*lease/i,
    )
  })

  it.each([
    ['base URL', { baseUrl: 'not a URL' }],
    ['base URL', { baseUrl: 'file:///tmp/glocke' }],
    ['base URL', { baseUrl: 'https://user:password@glocke.example' }],
    ['source', { source: '   ' }],
    ['source', { source: 'Invalid_Service' }],
    ['key ID', { keyId: '' }],
    ['key ID', { keyId: 'invalid key' }],
    ['string secret', { secret: 'too-short' }],
    ['byte secret', { secret: new Uint8Array(31) }],
  ])('rejects an invalid %s before claiming a row', (_description, override) => {
    const claim = vi.fn(async () => row)

    expect(() => setup({ claim, ...override })).toThrow()
    expect(claim).not.toHaveBeenCalled()
  })

  const numericOptionNames = [
    'leaseDurationMs',
    'requestTimeoutMs',
    'pollIntervalMs',
    'stopTimeoutMs',
    'maxAttempts',
    'baseDelayMs',
    'maxDelayMs',
  ] as const
  const invalidNumericValues = [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]

  it.each(numericOptionNames.flatMap((name) => invalidNumericValues.map((value) => [name, value] as const)))(
    'rejects invalid numeric option %s=%s before claiming a row',
    (name, value) => {
      const claim = vi.fn(async () => row)

      expect(() => setup({ claim, [name]: value })).toThrow()
      expect(claim).not.toHaveBeenCalled()
    },
  )

  it.each(['requestTimeoutMs', 'pollIntervalMs', 'stopTimeoutMs'] as const)(
    'rejects %s above Node\'s maximum timer delay',
    (name) => {
      const claim = vi.fn(async () => row)

      expect(() => setup({ claim, [name]: MAX_TIMER_MS + 1 })).toThrow(/maximum timer/i)
      expect(claim).not.toHaveBeenCalled()
    },
  )

  it.each(['leaseDurationMs', 'maxDelayMs'] as const)(
    'rejects date duration %s above the JavaScript Date range',
    (name) => {
      expect(() => setup({ [name]: MAX_DATE_MS + 1 })).toThrow(/date/i)
    },
  )

  it('rejects a base retry delay above the maximum delay', () => {
    expect(() => setup({ baseDelayMs: 2_000, maxDelayMs: 1_000 })).toThrow(/retry delay/i)
  })

  it('rejects date-overflowing lease and retry combinations before claiming', async () => {
    const claim = vi.fn(async () => row)
    const { runtime } = setup({ claim, now: () => MAX_DATE_MS - 1_000 })

    await expect(runtime.deliverOne()).rejects.toThrow(/date/i)
    expect(claim).not.toHaveBeenCalled()
  })

  it('records an ordinary fetch rejection as a sanitized bounded retry with backoff', async () => {
    const fetch = vi.fn(async () => {
      throw new Error('getaddrinfo ENOTFOUND private.internal')
    })
    const { runtime, markRetry, markPermanent } = setup({ fetch })

    await expect(runtime.deliverOne()).resolves.toBe('retry')

    expect(markRetry).toHaveBeenCalledWith({
      id: EVENT_ID,
      leaseToken: 'lease-123',
      attempts: 1,
      nextAttemptAt: new Date(NOW_MS + 500),
      error: 'notification request failed',
    })
    expect(markPermanent).not.toHaveBeenCalled()
    expect(JSON.stringify(markRetry.mock.calls)).not.toContain('private.internal')
  })

  it('permanently fails an ordinary fetch rejection at the maximum attempt', async () => {
    const fetch = vi.fn(async () => {
      throw new Error('socket closed')
    })
    const claim = vi.fn(async () => ({ ...row, attempts: 4 }))
    const { runtime, markRetry, markPermanent } = setup({ fetch, claim, maxAttempts: 5 })

    await expect(runtime.deliverOne()).resolves.toBe('permanent')

    expect(markRetry).not.toHaveBeenCalled()
    expect(markPermanent).toHaveBeenCalledWith({
      id: EVENT_ID,
      leaseToken: 'lease-123',
      attempts: 5,
      error: 'notification request failed; maximum attempts reached',
    })
  })

  it('aborts a timed-out request and records a sanitized retry', async () => {
    vi.useFakeTimers()
    const fetch = vi.fn((_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(init.signal?.reason))
      }),
    )
    const { runtime, markRetry } = setup({ fetch })
    const delivery = runtime.deliverOne()

    await vi.advanceTimersByTimeAsync(5_000)
    await expect(delivery).resolves.toBe('retry')

    expect(fetch.mock.calls[0]?.[1].signal?.aborted).toBe(true)
    expect(markRetry).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'notification request timed out', attempts: 1 }),
    )
  })

  it('permanently fails a timeout at the maximum attempt', async () => {
    vi.useFakeTimers()
    const fetch = vi.fn((_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(init.signal?.reason))
      }),
    )
    const claim = vi.fn(async () => ({ ...row, attempts: 4 }))
    const { runtime, markRetry, markPermanent } = setup({ fetch, claim, maxAttempts: 5 })
    const delivery = runtime.deliverOne()

    await vi.advanceTimersByTimeAsync(5_000)
    await expect(delivery).resolves.toBe('permanent')

    expect(markRetry).not.toHaveBeenCalled()
    expect(markPermanent).toHaveBeenCalledWith({
      id: EVENT_ID,
      leaseToken: 'lease-123',
      attempts: 5,
      error: 'notification request timed out; maximum attempts reached',
    })
  })

  it('cancels the response body after classifying the response', async () => {
    const cancel = vi.fn()
    const body = new ReadableStream({ cancel })
    const fetch = vi.fn(async () => new Response(body, { status: 503 }))
    const { runtime } = setup({ fetch })

    await runtime.deliverOne()

    expect(cancel).toHaveBeenCalledOnce()
  })

  it('does not wait for response body cancellation before settling', async () => {
    const pendingCancel = deferred<void>()
    const body = new ReadableStream({ cancel: () => pendingCancel.promise })
    const fetch = vi.fn(async () => new Response(body, { status: 503 }))
    const { runtime, markRetry } = setup({ fetch })

    await expect(runtime.deliverOne()).resolves.toBe('retry')
    expect(markRetry).toHaveBeenCalledOnce()
    pendingCancel.resolve()
  })

  it.each([
    ['delivered', { fetch: vi.fn(async () => new Response(null, { status: 204 })), markDelivered: vi.fn(async () => false) }],
    ['retry', { fetch: vi.fn(async () => new Response(null, { status: 503 })), markRetry: vi.fn(async () => false) }],
    ['permanent', { fetch: vi.fn(async () => new Response(null, { status: 400 })), markPermanent: vi.fn(async () => false) }],
  ])('reports a false fenced %s settlement as stale', async (_description, overrides) => {
    const { runtime } = setup(overrides)

    await expect(runtime.deliverOne()).resolves.toBe('stale')
  })
})

describe('notification outbox polling lifecycle', () => {
  it('never overlaps claims when a polling iteration is still running', async () => {
    vi.useFakeTimers()
    const pendingClaim = deferred<null>()
    const claim = vi.fn(() => pendingClaim.promise)
    const { runtime } = setup({ claim })

    runtime.start()
    await vi.advanceTimersByTimeAsync(5_000)
    expect(claim).toHaveBeenCalledOnce()

    pendingClaim.resolve(null)
    await vi.advanceTimersByTimeAsync(1_000)
    expect(claim).toHaveBeenCalledTimes(2)
    await runtime.stop()
  })

  it('stop aborts in-flight delivery and resolves within the configured bound', async () => {
    vi.useFakeTimers()
    const fetch = vi.fn((_url: string, _init: RequestInit) => new Promise<Response>(() => {}))
    const { runtime } = setup({ fetch, requestTimeoutMs: 20_000, stopTimeoutMs: 2_000 })

    runtime.start()
    await vi.advanceTimersByTimeAsync(0)
    const stopped = runtime.stop()
    await vi.advanceTimersByTimeAsync(2_000)

    await expect(stopped).resolves.toBeUndefined()
    expect(fetch.mock.calls[0]?.[1].signal?.aborted).toBe(true)
  })

  it('does not persist a stop-triggered abort as a network failure', async () => {
    vi.useFakeTimers()
    const fetch = vi.fn((_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(init.signal?.reason))
      }),
    )
    const { runtime, markDelivered, markRetry, markPermanent } = setup({ fetch })

    runtime.start()
    await vi.advanceTimersByTimeAsync(0)
    await runtime.stop()

    expect(markDelivered).not.toHaveBeenCalled()
    expect(markRetry).not.toHaveBeenCalled()
    expect(markPermanent).not.toHaveBeenCalled()
  })

  it('does not overlap a restarted poller with a stale run left behind by stop', async () => {
    vi.useFakeTimers()
    const pendingResponse = deferred<Response>()
    const fetch = vi.fn(() => pendingResponse.promise)
    const claim = vi.fn(async () => row)
    const { runtime } = setup({ fetch, claim, requestTimeoutMs: 20_000, stopTimeoutMs: 2_000 })

    runtime.start()
    await vi.advanceTimersByTimeAsync(0)
    const stopped = runtime.stop()
    await vi.advanceTimersByTimeAsync(2_000)
    await stopped

    runtime.start()
    await vi.advanceTimersByTimeAsync(0)
    const claimsBeforeStaleRunSettled = claim.mock.calls.length

    pendingResponse.resolve(new Response(null, { status: 204 }))
    await vi.advanceTimersByTimeAsync(0)
    await runtime.stop()

    expect(claimsBeforeStaleRunSettled).toBe(1)
  })

  it('does not let a pre-stop claim adopt the restarted generation controller', async () => {
    vi.useFakeTimers()
    const pendingClaim = deferred<typeof row>()
    const claim = vi.fn(() => pendingClaim.promise)
    const { runtime, fetch, markDelivered, markRetry, markPermanent } = setup({
      claim,
      stopTimeoutMs: 2_000,
    })

    runtime.start()
    await vi.advanceTimersByTimeAsync(0)
    const stopped = runtime.stop()
    await vi.advanceTimersByTimeAsync(2_000)
    await stopped
    runtime.start()

    pendingClaim.resolve(row)
    await vi.advanceTimersByTimeAsync(0)

    expect(fetch).not.toHaveBeenCalled()
    expect(markDelivered).not.toHaveBeenCalled()
    expect(markRetry).not.toHaveBeenCalled()
    expect(markPermanent).not.toHaveBeenCalled()
    await runtime.stop()
  })

  it('does not let response body cancellation block the next poll', async () => {
    vi.useFakeTimers()
    const pendingCancel = deferred<void>()
    const body = new ReadableStream({ cancel: () => pendingCancel.promise })
    const fetch = vi.fn(async () => new Response(body, { status: 503 }))
    const claim = vi.fn()
      .mockResolvedValueOnce(row)
      .mockResolvedValueOnce(null)
    const { runtime } = setup({ fetch, claim })

    runtime.start()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(1_000)

    expect(claim).toHaveBeenCalledTimes(2)
    await runtime.stop()
    pendingCancel.resolve()
  })
})

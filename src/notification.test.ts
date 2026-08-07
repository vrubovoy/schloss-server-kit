import { describe, expect, it } from 'vitest'
import {
  calculateBackoffDelay,
  classifyNotificationResponse,
  correlationIdSchema,
  notificationEventEnvelopeSchema,
  parseRetryAfter,
  requestIdSchema,
  signNotificationRequest,
  verifyNotificationRequest,
} from './notification.js'

const REQUEST_ID = '123e4567-e89b-42d3-a456-426614174000'
const CORRELATION_ID = '987fcdeb-51a2-43d7-b654-123456789abc'

describe('notification event envelope', () => {
  const validEnvelope = {
    version: '1',
    id: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    type: 'reminder.due',
    source: 'kalender',
    occurredAt: '2026-08-07T12:00:00.000Z',
    correlationId: CORRELATION_ID,
    payload: { reminderId: 'reminder-123', minutesBefore: 15 },
  }

  it('accepts a version 1 envelope without depending on a domain payload schema', () => {
    expect(notificationEventEnvelopeSchema.parse(validEnvelope)).toEqual(validEnvelope)
  })

  it.each([
    ['an unsupported version', { version: '2' }],
    ['a malformed event ID', { id: 'event-123' }],
    ['an empty event type', { type: '' }],
    ['an empty source', { source: '' }],
    ['a malformed occurrence timestamp', { occurredAt: '7 August 2026' }],
    ['a malformed correlation ID', { correlationId: 'correlation-123' }],
  ])('rejects %s', (_description, override) => {
    expect(notificationEventEnvelopeSchema.safeParse({ ...validEnvelope, ...override }).success).toBe(false)
  })
})

describe('transport IDs', () => {
  it('accepts UUID request and correlation IDs', () => {
    expect(requestIdSchema.parse(REQUEST_ID)).toBe(REQUEST_ID)
    expect(correlationIdSchema.parse(CORRELATION_ID)).toBe(CORRELATION_ID)
  })

  it.each(['', 'request-123', ' 123e4567-e89b-42d3-a456-426614174000 ', '00000000-0000-0000-0000-000000000000'])(
    'rejects malformed transport ID %j',
    (value) => {
      expect(requestIdSchema.safeParse(value).success).toBe(false)
      expect(correlationIdSchema.safeParse(value).success).toBe(false)
    },
  )
})

describe('notification request signing', () => {
  const request = {
    secret: 'test-secret',
    keyId: 'key-2026-01',
    source: 'kalender',
    timestamp: 1_720_000_000,
    method: 'post',
    path: '/internal/notifications?tenant=hof',
    rawBody: '{"message":"door open","count":2}',
  }

  it('matches the canonical HMAC SHA-256 test vector', () => {
    // Canonical bytes are timestamp, uppercase method, path, raw-body SHA-256,
    // key ID, and source, joined in that order with a single LF.
    expect(signNotificationRequest(request)).toBe(
      '64ab00621036707a684a314dded64b584be4d49d4c7d9a5540e64a7e74353c14',
    )
  })

  it('signs the exact raw bytes without requiring a parsed body', () => {
    expect(
      signNotificationRequest({
        ...request,
        rawBody: new TextEncoder().encode(request.rawBody),
      }),
    ).toBe(signNotificationRequest(request))
  })

  it('verifies an authentic request at the timestamp skew boundary', () => {
    const signature = signNotificationRequest(request)

    expect(
      verifyNotificationRequest({
        ...request,
        signature,
        expectedKeyId: request.keyId,
        expectedSource: request.source,
        maxSkewSeconds: 300,
        now: () => (request.timestamp + 300) * 1_000,
      }),
    ).toBe(true)
  })

  it.each([
    ['method', { method: 'PUT' }],
    ['path, including its query string', { path: '/internal/notifications?tenant=other' }],
    ['raw body bytes', { rawBody: '{ "message":"door open","count":2}' }],
    ['key ID', { keyId: 'key-2026-02' }],
    ['source', { source: 'aufgaben' }],
  ])('rejects a signature when the %s changes', (_description, override) => {
    const signature = signNotificationRequest(request)

    expect(
      verifyNotificationRequest({
        ...request,
        ...override,
        signature,
        expectedKeyId: request.keyId,
        expectedSource: request.source,
        maxSkewSeconds: 300,
        now: () => request.timestamp * 1_000,
      }),
    ).toBe(false)
  })

  it.each([
    ['key ID', { keyId: 'attacker-key' }],
    ['source', { source: 'attacker-service' }],
  ])('rejects a correctly signed request whose %s is not the expected identity', (_description, identity) => {
    const signedRequest = { ...request, ...identity }

    expect(
      verifyNotificationRequest({
        ...signedRequest,
        signature: signNotificationRequest(signedRequest),
        expectedKeyId: request.keyId,
        expectedSource: request.source,
        maxSkewSeconds: 300,
        now: () => request.timestamp * 1_000,
      }),
    ).toBe(false)
  })

  it.each([
    ['too old', -301],
    ['too far in the future', 301],
  ])('rejects an authentic timestamp that is %s using injected current time', (_description, offsetSeconds) => {
    const timestamp = request.timestamp + offsetSeconds
    const timestampedRequest = { ...request, timestamp }

    expect(
      verifyNotificationRequest({
        ...timestampedRequest,
        signature: signNotificationRequest(timestampedRequest),
        expectedKeyId: request.keyId,
        expectedSource: request.source,
        maxSkewSeconds: 300,
        now: () => request.timestamp * 1_000,
      }),
    ).toBe(false)
  })

  it.each(['', 'not-hex', 'aa', 'g'.repeat(64), 'a'.repeat(66)])(
    'safely returns false for an invalid signature %j instead of throwing on unequal buffers',
    (signature) => {
      const verify = () =>
        verifyNotificationRequest({
          ...request,
          signature,
          expectedKeyId: request.keyId,
          expectedSource: request.source,
          maxSkewSeconds: 300,
          now: () => request.timestamp * 1_000,
        })

      expect(verify).not.toThrow()
      expect(verify()).toBe(false)
    },
  )
})

describe('notification response retry classification', () => {
  it('classifies every 2xx response as success', () => {
    for (let status = 200; status <= 299; status += 1) {
      expect(classifyNotificationResponse(status)).toBe('success')
    }
  })

  it('classifies 408, 425, 429, and every 5xx response as retryable', () => {
    for (const status of [408, 425, 429]) {
      expect(classifyNotificationResponse(status)).toBe('retryable')
    }
    for (let status = 500; status <= 599; status += 1) {
      expect(classifyNotificationResponse(status)).toBe('retryable')
    }
  })

  it('classifies every other 4xx response as a permanent failure', () => {
    for (let status = 400; status <= 499; status += 1) {
      if (status !== 408 && status !== 425 && status !== 429) {
        expect(classifyNotificationResponse(status)).toBe('permanent')
      }
    }
  })
})

describe('Retry-After parsing', () => {
  const nowMs = Date.parse('2026-08-07T12:00:00.000Z')
  const options = { now: () => nowMs }

  it('parses delay-seconds into milliseconds', () => {
    expect(parseRetryAfter('120', options)).toBe(120_000)
    expect(parseRetryAfter(' 60 ', options)).toBe(60_000)
  })

  it('parses an HTTP date relative to injected current time', () => {
    expect(parseRetryAfter('Fri, 07 Aug 2026 12:02:00 GMT', options)).toBe(120_000)
  })

  it('returns zero for an HTTP date in the past', () => {
    expect(parseRetryAfter('Fri, 07 Aug 2026 11:59:00 GMT', options)).toBe(0)
  })

  it.each([null, '', '-1', '1.5', 'eventually'])('returns undefined for invalid value %j', (value) => {
    expect(parseRetryAfter(value, options)).toBeUndefined()
  })
})

describe('exponential backoff', () => {
  it('uses the injected randomness for full jitter', () => {
    expect(
      calculateBackoffDelay({
        attempt: 3,
        baseDelayMs: 1_000,
        maxDelayMs: 30_000,
        random: () => 0.5,
      }),
    ).toBe(4_000)
  })

  it('starts attempt zero at the base delay window', () => {
    expect(
      calculateBackoffDelay({
        attempt: 0,
        baseDelayMs: 1_000,
        maxDelayMs: 30_000,
        random: () => 0.999,
      }),
    ).toBe(999)
  })

  it('caps the exponential delay before applying jitter', () => {
    expect(
      calculateBackoffDelay({
        attempt: 10,
        baseDelayMs: 1_000,
        maxDelayMs: 30_000,
        random: () => 0.5,
      }),
    ).toBe(15_000)
  })

  it('can choose the start of the jitter window deterministically', () => {
    expect(
      calculateBackoffDelay({
        attempt: 4,
        baseDelayMs: 1_000,
        maxDelayMs: 30_000,
        random: () => 0,
      }),
    ).toBe(0)
  })
})

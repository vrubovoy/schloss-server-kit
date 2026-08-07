import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'

const NIL_UUID = '00000000-0000-0000-0000-000000000000'

const transportIdSchema = z.uuid().refine((value) => value.toLowerCase() !== NIL_UUID, 'ID must not be the nil UUID')

export const requestIdSchema = transportIdSchema
export const correlationIdSchema = transportIdSchema

export const notificationEventEnvelopeSchema = z.object({
  version: z.literal('1'),
  id: transportIdSchema,
  type: z.string().min(1),
  source: z.string().min(1),
  occurredAt: z.iso.datetime(),
  correlationId: correlationIdSchema,
  payload: z.unknown(),
})

export type NotificationEventEnvelope = z.infer<typeof notificationEventEnvelopeSchema>

export interface SignNotificationRequestOptions {
  secret: string | Uint8Array
  keyId: string
  source: string
  timestamp: number
  method: string
  path: string
  rawBody: string | Uint8Array
}

export interface VerifyNotificationRequestOptions extends SignNotificationRequestOptions {
  signature: string
  expectedKeyId: string
  expectedSource: string
  maxSkewSeconds: number
  now?: () => number
}

function canonicalNotificationRequest(options: SignNotificationRequestOptions): string {
  const bodyHash = createHash('sha256').update(options.rawBody).digest('hex')

  return [
    options.timestamp,
    options.method.toUpperCase(),
    options.path,
    bodyHash,
    options.keyId,
    options.source,
  ].join('\n')
}

export function signNotificationRequest(options: SignNotificationRequestOptions): string {
  return createHmac('sha256', options.secret).update(canonicalNotificationRequest(options)).digest('hex')
}

export function verifyNotificationRequest(options: VerifyNotificationRequestOptions): boolean {
  const {
    signature,
    expectedKeyId,
    expectedSource,
    maxSkewSeconds,
    now = Date.now,
    ...request
  } = options

  if (
    request.keyId !== expectedKeyId ||
    request.source !== expectedSource ||
    !Number.isInteger(request.timestamp) ||
    !Number.isFinite(maxSkewSeconds) ||
    maxSkewSeconds < 0 ||
    Math.abs(now() / 1_000 - request.timestamp) > maxSkewSeconds ||
    !/^[0-9a-f]{64}$/i.test(signature)
  ) {
    return false
  }

  const expectedSignature = Buffer.from(signNotificationRequest(request), 'hex')
  const receivedSignature = Buffer.from(signature, 'hex')

  return timingSafeEqual(receivedSignature, expectedSignature)
}

export type NotificationResponseClassification = 'success' | 'retryable' | 'permanent'

export function classifyNotificationResponse(status: number): NotificationResponseClassification {
  if (status >= 200 && status <= 299) return 'success'
  if (status === 408 || status === 425 || status === 429 || (status >= 500 && status <= 599)) {
    return 'retryable'
  }
  return 'permanent'
}

export interface ParseRetryAfterOptions {
  now?: () => number
}

const HTTP_DATE_PATTERN =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/

export function parseRetryAfter(
  value: string | null | undefined,
  options: ParseRetryAfterOptions = {},
): number | undefined {
  const trimmedValue = value?.trim()
  if (!trimmedValue) return undefined

  if (/^\d+$/.test(trimmedValue)) {
    const seconds = Number(trimmedValue)
    return Number.isSafeInteger(seconds) && seconds <= Number.MAX_SAFE_INTEGER / 1_000
      ? seconds * 1_000
      : undefined
  }

  if (!HTTP_DATE_PATTERN.test(trimmedValue)) return undefined

  const dateMs = Date.parse(trimmedValue)
  if (!Number.isFinite(dateMs) || new Date(dateMs).toUTCString() !== trimmedValue) return undefined

  const nowMs = (options.now ?? Date.now)()
  return Number.isFinite(nowMs) ? Math.max(0, dateMs - nowMs) : undefined
}

export interface CalculateBackoffDelayOptions {
  attempt: number
  baseDelayMs: number
  maxDelayMs: number
  random?: () => number
}

export function calculateBackoffDelay(options: CalculateBackoffDelayOptions): number {
  const { attempt, baseDelayMs, maxDelayMs, random = Math.random } = options
  const delayWindow = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt)

  return Math.floor(random() * delayWindow)
}

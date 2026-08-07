import {
  calculateBackoffDelay,
  classifyNotificationResponse,
  notificationEventEnvelopeSchema,
  parseRetryAfter,
  signNotificationRequest,
} from './notification.js'

const EVENTS_PATH = '/internal/v1/events'

export interface NotificationOutboxRow {
  id: string
  type: string
  occurredAt: string
  correlationId: string
  payload: unknown
  attempts: number
  leaseToken: string
}

export interface ClaimOutboxRowArgs {
  now: Date
  leaseUntil: Date
}

export interface MarkDeliveredArgs {
  id: string
  leaseToken: string
  deliveredAt: Date
}

export interface MarkRetryArgs {
  id: string
  leaseToken: string
  attempts: number
  nextAttemptAt: Date
  error: string
}

export interface MarkPermanentArgs {
  id: string
  leaseToken: string
  attempts: number
  error: string
}

export type DeliverOneResult = 'delivered' | 'retry' | 'permanent' | 'idle'

export interface CreateNotificationOutboxRuntimeOptions {
  /** This service's own name, sent as `source`/`X-Hof-Service` and signed into every request. */
  source: string
  keyId: string
  secret: string | Uint8Array
  /** Only its origin is used - the events path is always exactly `/internal/v1/events`, any path on baseUrl is ignored. */
  baseUrl: string
  /**
   * Storage is entirely the caller's own responsibility - this runtime is
   * storage-agnostic on purpose, so each service keeps its own SQLite
   * transaction/dedupe policy rather than sharing one here. `claim` must
   * atomically lease exactly one eligible row (or return null); the three
   * `mark*` callbacks must condition their update on the given
   * `leaseToken` so a lease that's since expired/been re-claimed can't be
   * clobbered by a stale delivery attempt racing behind it.
   */
  claim: (args: ClaimOutboxRowArgs) => Promise<NotificationOutboxRow | null>
  markDelivered: (args: MarkDeliveredArgs) => Promise<boolean>
  markRetry: (args: MarkRetryArgs) => Promise<boolean>
  markPermanent: (args: MarkPermanentArgs) => Promise<boolean>
  // Narrower than the real global fetch's (input: string | URL | Request,
  // init?) signature on purpose - this runtime only ever calls it with a
  // plain string URL and a concrete RequestInit, and narrowing the
  // injection point's type to exactly that lets a test double declare the
  // same narrow signature without having to satisfy the full real one.
  fetch?: (url: string, init: RequestInit) => Promise<Response>
  now?: () => number
  random?: () => number
  leaseDurationMs: number
  /** Must be strictly shorter than leaseDurationMs, so a timed-out request never outlives its own lease. */
  requestTimeoutMs: number
  pollIntervalMs: number
  /** Upper bound on how long stop() waits for an in-flight delivery to actually finish before giving up and returning anyway. */
  stopTimeoutMs: number
  maxAttempts: number
  baseDelayMs: number
  maxDelayMs: number
}

export interface NotificationOutboxRuntime {
  /** One claim-deliver-settle cycle - also what the polling loop below calls repeatedly. */
  deliverOne(): Promise<DeliverOneResult>
  start(): void
  /** Aborts any in-flight request and stops scheduling further polls; resolves once the in-flight delivery settles or stopTimeoutMs elapses, whichever comes first. */
  stop(): Promise<void>
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// A transactional-outbox delivery loop shared by every producer service:
// claim one pending row, sign and POST it to Glocke's ingestion endpoint,
// and record the outcome back through the caller's own storage callbacks.
// Deliberately storage-agnostic (see `claim`'s own doc comment) - the only
// thing every service shares is this delivery/retry/backoff mechanics, not
// how the outbox table itself is modeled.
export function createNotificationOutboxRuntime(
  options: CreateNotificationOutboxRuntimeOptions,
): NotificationOutboxRuntime {
  const {
    source, keyId, secret, baseUrl, claim, markDelivered, markRetry, markPermanent,
    fetch: fetchImpl = fetch,
    now = Date.now,
    random = Math.random,
    leaseDurationMs, requestTimeoutMs, pollIntervalMs, stopTimeoutMs,
    maxAttempts, baseDelayMs, maxDelayMs,
  } = options

  if (requestTimeoutMs >= leaseDurationMs) {
    throw new Error('request timeout must be shorter than the lease duration, or a timed-out request could outlive its own lease')
  }

  let polling = false
  let stopping = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let inFlight: Promise<DeliverOneResult> | undefined
  let stopController = new AbortController()

  function backoffDelay(attempt: number): number {
    return calculateBackoffDelay({ attempt, baseDelayMs, maxDelayMs, random })
  }

  async function deliverOne(): Promise<DeliverOneResult> {
    const nowMs = now()
    const row = await claim({ now: new Date(nowMs), leaseUntil: new Date(nowMs + leaseDurationMs) })
    if (!row) return 'idle'

    const envelope = {
      version: '1' as const,
      id: row.id,
      type: row.type,
      source,
      occurredAt: row.occurredAt,
      correlationId: row.correlationId,
      payload: row.payload,
    }

    let rawBody: string
    try {
      rawBody = JSON.stringify(envelope)
      if (typeof rawBody !== 'string') throw new Error('envelope serialized to undefined')
      if (!notificationEventEnvelopeSchema.safeParse(envelope).success) throw new Error('envelope failed schema validation')
    } catch {
      // Never include the row itself in the error - it's arbitrary
      // domain data from the caller, not something safe to persist/log
      // verbatim (mirrors never reading a failed response's own body below).
      await markPermanent({ id: row.id, leaseToken: row.leaseToken, attempts: row.attempts + 1, error: 'invalid notification outbox row' })
      return 'permanent'
    }

    const timestamp = Math.floor(nowMs / 1_000)
    const url = new URL(EVENTS_PATH, baseUrl).href
    const signature = signNotificationRequest({ secret, keyId, source, timestamp, method: 'POST', path: EVENTS_PATH, rawBody })
    const headers = {
      'Content-Type': 'application/json',
      'X-Hof-Key-Id': keyId,
      'X-Hof-Service': source,
      'X-Hof-Timestamp': String(timestamp),
      'X-Hof-Signature': signature,
    }

    const timeoutController = new AbortController()
    const timeoutId = setTimeout(
      () => timeoutController.abort(new Error('notification request timed out')),
      requestTimeoutMs,
    )
    const signal = AbortSignal.any([timeoutController.signal, stopController.signal])

    let response: Response
    try {
      response = await fetchImpl(url, { method: 'POST', headers, body: rawBody, signal })
    } catch (err) {
      clearTimeout(timeoutId)
      if (timeoutController.signal.aborted) {
        const attempts = row.attempts + 1
        await markRetry({
          id: row.id,
          leaseToken: row.leaseToken,
          attempts,
          nextAttemptAt: new Date(nowMs + backoffDelay(row.attempts)),
          error: 'notification request timed out',
        })
        return 'retry'
      }
      // Aborted by stop() (or a genuine network error) - not a delivery
      // outcome to persist. The polling loop swallows this; a direct
      // deliverOne() caller sees the rejection.
      throw err
    }
    clearTimeout(timeoutId)

    const classification = classifyNotificationResponse(response.status)
    if (classification === 'success') {
      await markDelivered({ id: row.id, leaseToken: row.leaseToken, deliveredAt: new Date(nowMs) })
      return 'delivered'
    }

    const attempts = row.attempts + 1
    if (classification === 'permanent') {
      await markPermanent({
        id: row.id, leaseToken: row.leaseToken, attempts,
        error: `notification endpoint returned HTTP ${response.status}`,
      })
      return 'permanent'
    }

    // classification === 'retryable'
    if (attempts >= maxAttempts) {
      await markPermanent({
        id: row.id, leaseToken: row.leaseToken, attempts,
        error: `notification endpoint returned HTTP ${response.status}; maximum attempts reached`,
      })
      return 'permanent'
    }

    const retryAfterMs = parseRetryAfter(response.headers.get('Retry-After'), { now })
    await markRetry({
      id: row.id, leaseToken: row.leaseToken, attempts,
      nextAttemptAt: new Date(nowMs + (retryAfterMs ?? backoffDelay(row.attempts))),
      error: `notification endpoint returned HTTP ${response.status}`,
    })
    return 'retry'
  }

  function scheduleNext() {
    if (stopping) return
    timer = setTimeout(runOnce, pollIntervalMs)
  }

  function runOnce() {
    inFlight = deliverOne()
      .catch((): DeliverOneResult => 'idle')
      .finally(() => {
        inFlight = undefined
        scheduleNext()
      })
  }

  return {
    deliverOne,
    start() {
      if (polling) return
      polling = true
      stopping = false
      stopController = new AbortController()
      runOnce()
    },
    async stop() {
      stopping = true
      polling = false
      if (timer) clearTimeout(timer)
      stopController.abort(new Error('notification outbox runtime stopped'))
      if (inFlight) {
        await Promise.race([inFlight.then(() => undefined).catch(() => undefined), delay(stopTimeoutMs)])
      }
    },
  }
}

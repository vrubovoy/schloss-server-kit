import {
  calculateBackoffDelay,
  classifyNotificationResponse,
  notificationEventEnvelopeSchema,
  parseRetryAfter,
  signNotificationRequest,
} from './notification.js'

const EVENTS_PATH = '/internal/v1/events'
const MAX_TIMER_MS = 2_147_483_647
const MAX_DATE_MS = 8_640_000_000_000_000

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

export type DeliverOneResult = 'delivered' | 'retry' | 'permanent' | 'idle' | 'stale'

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

function isInternalHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost') || !host.includes('.')) return true
  if (host.endsWith('.internal') || host.endsWith('.local')) return true

  const octets = host.split('.').map(Number)
  if (octets.length === 4 && octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)) {
    return octets[0] === 10
      || octets[0] === 127
      || (octets[0] === 169 && octets[1] === 254)
      || (octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31)
      || (octets[0] === 192 && octets[1] === 168)
  }

  return host === '::1' || /^f[cd][0-9a-f]*:/i.test(host) || /^fe[89ab][0-9a-f]*:/i.test(host)
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

  if (!/^[a-z][a-z0-9-]{0,63}$/.test(source)) {
    throw new Error('notification source must be a lowercase service name')
  }
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(keyId)) {
    throw new Error('notification key ID has an invalid format')
  }
  const secretLength = typeof secret === 'string' ? new TextEncoder().encode(secret).byteLength : secret.byteLength
  if (secretLength < 32) throw new Error('notification secret must be at least 32 bytes')

  let base: URL
  try {
    base = new URL(baseUrl)
  } catch {
    throw new Error('notification base URL must be a valid absolute URL')
  }
  if (
    base.username || base.password
    || (base.protocol !== 'https:' && !(base.protocol === 'http:' && isInternalHostname(base.hostname)))
  ) {
    throw new Error('notification base URL must use HTTPS or internal HTTP')
  }

  const numericOptions = {
    leaseDurationMs, requestTimeoutMs, pollIntervalMs, stopTimeoutMs,
    maxAttempts, baseDelayMs, maxDelayMs,
  }
  for (const [name, value] of Object.entries(numericOptions)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error(`${name} must be a positive safe integer`)
    }
  }
  const timerOptions = { requestTimeoutMs, pollIntervalMs, stopTimeoutMs }
  for (const [name, value] of Object.entries(timerOptions)) {
    if (value > MAX_TIMER_MS) throw new Error(`${name} exceeds Node's maximum timer delay`)
  }
  if (leaseDurationMs > MAX_DATE_MS || maxDelayMs > MAX_DATE_MS) {
    throw new Error('notification lease and retry delays must fit in a JavaScript Date')
  }
  if (baseDelayMs > maxDelayMs) {
    throw new Error('notification base retry delay must not exceed the maximum delay')
  }
  if (requestTimeoutMs >= leaseDurationMs) {
    throw new Error('request timeout must be shorter than the lease duration, or a timed-out request could outlive its own lease')
  }

  const eventsUrl = new URL(EVENTS_PATH, base.origin).href

  let polling = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let inFlight: Promise<DeliverOneResult> | undefined
  let stopController = new AbortController()

  function backoffDelay(attempt: number): number {
    return calculateBackoffDelay({ attempt, baseDelayMs, maxDelayMs, random })
  }

  async function deliverOne(): Promise<DeliverOneResult> {
    const stopSignal = stopController.signal
    const nowMs = now()
    const leaseUntilMs = nowMs + leaseDurationMs
    const latestRetryMs = nowMs + maxDelayMs
    if (
      !Number.isSafeInteger(nowMs)
      || Math.abs(nowMs) > MAX_DATE_MS
      || Math.abs(leaseUntilMs) > MAX_DATE_MS
      || Math.abs(latestRetryMs) > MAX_DATE_MS
    ) {
      throw new Error('notification time and configured delays must fit in a JavaScript Date')
    }

    const row = await claim({ now: new Date(nowMs), leaseUntil: new Date(leaseUntilMs) })
    if (stopSignal.aborted) throw stopSignal.reason
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
      const settled = await markPermanent({ id: row.id, leaseToken: row.leaseToken, attempts: row.attempts + 1, error: 'invalid notification outbox row' })
      return settled ? 'permanent' : 'stale'
    }

    const timestamp = Math.floor(nowMs / 1_000)
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
    const signal = AbortSignal.any([timeoutController.signal, stopSignal])
    const transientRow = row

    async function settleTransient(error: string): Promise<DeliverOneResult> {
      const attempts = transientRow.attempts + 1
      if (attempts >= maxAttempts) {
        const settled = await markPermanent({
          id: transientRow.id,
          leaseToken: transientRow.leaseToken,
          attempts,
          error: `${error}; maximum attempts reached`,
        })
        return settled ? 'permanent' : 'stale'
      }
      const settled = await markRetry({
        id: transientRow.id,
        leaseToken: transientRow.leaseToken,
        attempts,
        nextAttemptAt: new Date(nowMs + backoffDelay(transientRow.attempts)),
        error,
      })
      return settled ? 'retry' : 'stale'
    }

    let response: Response
    try {
      response = await fetchImpl(eventsUrl, { method: 'POST', headers, body: rawBody, signal })
    } catch (error) {
      if (stopSignal.aborted) throw error
      if (timeoutController.signal.aborted) {
        return settleTransient('notification request timed out')
      }
      return settleTransient('notification request failed')
    } finally {
      clearTimeout(timeoutId)
    }

    const classification = classifyNotificationResponse(response.status)
    try {
      void response.body?.cancel().catch(() => undefined)
    } catch {
      // Classification and fenced settlement do not depend on body cleanup.
    }
    if (stopSignal.aborted) {
      throw stopSignal.reason
    }
    if (timeoutController.signal.aborted) {
      return settleTransient('notification request timed out')
    }
    if (classification === 'success') {
      const settled = await markDelivered({ id: row.id, leaseToken: row.leaseToken, deliveredAt: new Date(nowMs) })
      return settled ? 'delivered' : 'stale'
    }

    const attempts = row.attempts + 1
    if (classification === 'permanent') {
      const settled = await markPermanent({
        id: row.id, leaseToken: row.leaseToken, attempts,
        error: `notification endpoint returned HTTP ${response.status}`,
      })
      return settled ? 'permanent' : 'stale'
    }

    // classification === 'retryable'
    if (attempts >= maxAttempts) {
      const settled = await markPermanent({
        id: row.id, leaseToken: row.leaseToken, attempts,
        error: `notification endpoint returned HTTP ${response.status}; maximum attempts reached`,
      })
      return settled ? 'permanent' : 'stale'
    }

    const parsedRetryAfterMs = parseRetryAfter(response.headers.get('Retry-After'), { now })
    const retryAfterMs = parsedRetryAfterMs !== undefined && Math.abs(nowMs + parsedRetryAfterMs) <= MAX_DATE_MS
      ? parsedRetryAfterMs
      : undefined
    const settled = await markRetry({
      id: row.id, leaseToken: row.leaseToken, attempts,
      nextAttemptAt: new Date(nowMs + (retryAfterMs ?? backoffDelay(row.attempts))),
      error: `notification endpoint returned HTTP ${response.status}`,
    })
    return settled ? 'retry' : 'stale'
  }

  function scheduleNext() {
    if (!polling) return
    timer = setTimeout(runOnce, pollIntervalMs)
  }

  function runOnce() {
    timer = undefined
    if (!polling || inFlight) return
    const run = deliverOne().catch((): DeliverOneResult => 'idle')
    inFlight = run
    void run.finally(() => {
      if (inFlight === run) {
        inFlight = undefined
        scheduleNext()
      }
    })
  }

  return {
    deliverOne,
    start() {
      if (polling) return
      polling = true
      stopController = new AbortController()
      runOnce()
    },
    async stop() {
      polling = false
      if (timer) {
        clearTimeout(timer)
        timer = undefined
      }
      stopController.abort(new Error('notification outbox runtime stopped'))
      if (inFlight) {
        await Promise.race([inFlight.then(() => undefined).catch(() => undefined), delay(stopTimeoutMs)])
      }
    },
  }
}

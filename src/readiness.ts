const DEFAULT_TIMEOUT_MS = 2_000

export interface CheckJwksReachableOptions {
  timeoutMs?: number
  fetchImpl?: typeof fetch
}

// Every consuming backend authenticates through Schlüssel's JWKS - this is
// its one universally mandatory dependency, so /ready checking "is my own
// database schema current" without also checking "can I still reach the
// identity provider I'll reject every request against" reports healthy for
// a backend that's actually unable to authenticate anyone. Bounded to a
// short timeout so a slow/unreachable dependency degrades this service's
// own readiness promptly instead of hanging the health check itself.
export async function checkJwksReachable(
  jwksUrl: string,
  options: CheckJwksReachableOptions = {},
): Promise<boolean> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = fetch } = options
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetchImpl(jwksUrl, { signal: controller.signal })
    return response.ok
  } catch {
    return false
  } finally {
    clearTimeout(timeout)
  }
}

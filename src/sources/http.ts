// Shared HTTP helper for the source fetchers. Provides:
//   - fetchJson: GET + JSON parse with an AbortController timeout
//   - a token-bucket rate limiter sized for NVD's strict limits
//   - the optional NVD_API_KEY header (raises NVD's limit from 5 to 50 / 30s)
// Network is always best-effort; callers handle null / thrown errors.

export const NVD_API_KEY = process.env.NVD_API_KEY || ""

export class HttpError extends Error {
  constructor(public status: number, url: string) {
    super(`HTTP ${status} for ${url}`)
  }
}

export async function fetchJson<T = any>(
  url: string,
  opts: { headers?: Record<string, string>; timeoutMs?: number } = {},
): Promise<T> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 12000)
  try {
    const res = await fetch(url, {
      headers: { accept: "application/json", ...opts.headers },
      signal: ctrl.signal,
    })
    if (!res.ok) throw new HttpError(res.status, url)
    return (await res.json()) as T
  } finally {
    clearTimeout(timer)
  }
}

// A small token bucket: `capacity` tokens refilled over `windowMs`. NVD allows
// 5 req / 30s keyless and 50 with a key — leave a little headroom on each.
export class RateLimiter {
  private tokens: number
  private last = Date.now()
  constructor(
    private capacity: number,
    private windowMs: number,
  ) {
    this.tokens = capacity
  }

  private refill() {
    const now = Date.now()
    const gained = ((now - this.last) / this.windowMs) * this.capacity
    if (gained > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + gained)
      this.last = now
    }
  }

  async take(): Promise<void> {
    this.refill()
    while (this.tokens < 1) {
      const waitMs = Math.ceil((this.windowMs / this.capacity) * (1 - this.tokens)) + 25
      await new Promise((r) => setTimeout(r, waitMs))
      this.refill()
    }
    this.tokens -= 1
  }
}

// NVD bucket, sized to the active limit. Other feeds are generous; we don't
// throttle them.
export const nvdLimiter = new RateLimiter(NVD_API_KEY ? 45 : 4, 30000)

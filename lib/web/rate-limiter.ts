/**
 * Polite-mode rate limiter — global token bucket per origin.
 *
 * Without this, multiple parallel scanners (form-fuzzer + sqli + brute-login +
 * cve-pack on the same target) can collectively send hundreds of requests/sec
 * — small targets see this as a DoS. The limiter caps the *aggregate* rate.
 *
 * Drop-in: BrowsingSession.fetch() consults this before every request.
 *
 * Configuration (`POLITE_RATE_PER_SEC` env var, default 30/sec):
 *   - Higher → faster but more aggressive.
 *   - Lower → safer for small / fragile / shared infra.
 */

const RATE_PER_SEC = Math.max(1, Math.min(Number(process.env.POLITE_RATE_PER_SEC) || 30, 200));

interface Bucket {
  /** Tokens currently available (float). */
  tokens: number;
  /** Last refill timestamp (ms). */
  last: number;
}

declare global {
  // eslint-disable-next-line no-var
  var __mobaRateBuckets: Map<string, Bucket> | undefined;
}
const buckets = (globalThis.__mobaRateBuckets ??= new Map<string, Bucket>());

function originOf(url: string): string {
  try { return new URL(url).origin; } catch { return url; }
}

/** Wait until a token is available for the URL's origin, then return. */
export async function rateLimitFor(url: string): Promise<void> {
  const key = originOf(url);
  let b = buckets.get(key);
  if (!b) { b = { tokens: RATE_PER_SEC, last: Date.now() }; buckets.set(key, b); }
  for (;;) {
    const now = Date.now();
    const elapsedSec = (now - b.last) / 1000;
    if (elapsedSec > 0) {
      b.tokens = Math.min(RATE_PER_SEC, b.tokens + elapsedSec * RATE_PER_SEC);
      b.last = now;
    }
    if (b.tokens >= 1) { b.tokens -= 1; return; }
    // Sleep just long enough for the next token to be available.
    const wait = Math.max(5, Math.ceil((1 - b.tokens) * (1000 / RATE_PER_SEC)));
    await new Promise((r) => setTimeout(r, wait));
  }
}

export function rateLimitConfig() {
  return { ratePerSec: RATE_PER_SEC, originsTracked: buckets.size };
}

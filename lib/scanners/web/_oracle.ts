/**
 * Differential-probe oracle — the shared discipline that turns "the response
 * changed" into "the change is attributable to my payload, reproducible, and
 * not just noise / an error / a block."
 *
 * Every active scanner that decides a finding by diffing a probe response
 * against a baseline (param-miner, sqli boolean/blind, brute-login, header/
 * cookie injection, …) should route that decision through these primitives so
 * the false-positive floor is uniform and testable in one place.
 *
 * Motivated by a real scan against a CDN-fronted site that emitted 20 bogus
 * criticals and 462 bogus "hidden parameter" findings. Root causes, each
 * addressed by one rule below:
 *
 *   1. Non-signal responses were trusted. A `) AND (1=2` probe that the WAF
 *      dropped to a 0-byte / 4xx body was read as "SQL evaluated false."
 *      → `isNonSignal()` rejects empty / errored / newly-4xx-5xx responses.
 *   2. Fixed % thresholds ignored the page's own jitter. A homepage that
 *      naturally varied ±27 KB tripped a 5%-of-body threshold every time.
 *      → `noiseFloor()` measures jitter from repeated baselines; signals must
 *        clear `max(absoluteFloor, k × jitter)`.
 *   3. Volatile redirect targets read as "the redirect changed." Auth flows
 *      mint a fresh `state=`/`nonce=` per request.
 *      → `stableRedirect()` strips volatile params before comparing.
 *   4. No negative control. Reflection of a canary was called "param accepted"
 *      when the app simply echoes the whole URL for ANY param name.
 *      → callers pair the real probe with a control (see `attributable()`).
 *   5. No re-confirmation. One-shot diffs are flaky.
 *      → callers re-run and require the signal to reproduce.
 */

export interface ProbeResp {
  status: number;
  body: string;
  latencyMs: number;
  /** Final redirect target (last hop), if the request redirected. */
  redirect?: string | null;
}

/** Params whose values rotate per-request in auth / anti-CSRF / cache flows;
 *  a change in these must not count as "the response changed". */
const VOLATILE_PARAMS = new Set([
  "state", "nonce", "code", "code_challenge", "code_verifier", "session_state",
  "csrf", "csrf_token", "xsrf", "_token", "authenticity_token", "request_id",
  "requestid", "reqid", "ts", "timestamp", "_", "cb", "cachebuster", "rand",
  "sig", "signature",
]);

/**
 * Normalize a redirect target so volatile nonces don't make two equivalent
 * redirects look different. Drops known rotating params and sorts the rest.
 */
export function stableRedirect(target: string | null | undefined): string | null {
  if (!target) return null;
  try {
    const u = new URL(target);
    const kept: [string, string][] = [];
    for (const [k, v] of u.searchParams.entries()) {
      if (VOLATILE_PARAMS.has(k.toLowerCase())) continue;
      kept.push([k, v]);
    }
    kept.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const q = kept.map(([k, v]) => `${k}=${v}`).join("&");
    return `${u.origin}${u.pathname}${q ? "?" + q : ""}`;
  } catch {
    return target;
  }
}

/**
 * A response that carries no usable signal — trusting it produces false
 * positives. Empty body, transport failure (status 0), a challenge/rate-limit
 * status, or a 4xx/5xx that the baseline did NOT have (i.e. our payload got
 * blocked/errored, which is not evidence the app "did something").
 */
export function isNonSignal(resp: ProbeResp | null | undefined, baselineStatus?: number): boolean {
  if (!resp) return true;
  if (resp.status === 0) return true;
  if (resp.body.length === 0) return true;
  if (resp.status === 429 || resp.status === 503) return true; // throttle / challenge
  const baselineOk = baselineStatus === undefined || baselineStatus < 400;
  if (baselineOk && resp.status >= 400) return true; // payload got blocked/errored
  return false;
}

/**
 * Measure the page's natural body-length jitter from repeated baseline samples.
 * Returns the largest absolute deviation from the median length — the noise
 * floor a real signal must clear.
 */
export function noiseFloor(lengths: number[]): number {
  if (lengths.length < 2) return 0;
  const sorted = [...lengths].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  let maxDev = 0;
  for (const l of lengths) maxDev = Math.max(maxDev, Math.abs(l - median));
  return maxDev;
}

/** The median of a numeric list (used for a stable baseline length). */
export function median(nums: number[]): number {
  if (!nums.length) return 0;
  const s = [...nums].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

export interface Baseline {
  samples: ProbeResp[];
  /** Median body length across samples — the stable reference length. */
  len: number;
  /** Largest body-length deviation seen across samples (the noise floor). */
  jitter: number;
  /** Modal status across samples. */
  status: number;
  /** Normalized redirect target if the baselines agree on one, else null. */
  redirect: string | null;
  /** True if the baselines disagree on status or redirect target — the page is
   *  non-deterministic and length/redirect/status diffs cannot be trusted. */
  unstable: boolean;
}

/**
 * Take N baseline samples (default 2) of the untouched request and summarize
 * the page's stability envelope. `fetchOnce` performs one benign request.
 */
export async function measureBaseline(
  fetchOnce: () => Promise<ProbeResp | null>,
  n = 2,
): Promise<Baseline | null> {
  const samples: ProbeResp[] = [];
  for (let i = 0; i < Math.max(2, n); i++) {
    const r = await fetchOnce();
    if (!r || r.body.length === 0) return null; // can't baseline a blocked page
    samples.push(r);
  }
  const lens = samples.map((s) => s.body.length);
  const statuses = samples.map((s) => s.status);
  const redirects = samples.map((s) => stableRedirect(s.redirect ?? null));
  const status = statuses[0];
  const sameStatus = statuses.every((s) => s === status);
  const redirect = redirects[0];
  const sameRedirect = redirects.every((r) => r === redirect);
  return {
    samples,
    len: median(lens),
    jitter: noiseFloor(lens),
    status,
    redirect: sameRedirect ? redirect : null,
    unstable: !sameStatus || !sameRedirect,
  };
}

/** Effect-size gate: a length delta counts only if it clears both an absolute
 *  floor and a multiple of the measured jitter. */
export function exceedsNoise(delta: number, jitter: number, opts?: { absolute?: number; k?: number }): boolean {
  const absolute = opts?.absolute ?? 64;
  const k = opts?.k ?? 3;
  return Math.abs(delta) >= Math.max(absolute, jitter * k);
}

export type DiffSignal = "status-shift" | "redirect-shift" | "len-shift" | null;

/**
 * Classify a single probe response against a measured baseline into a
 * differential signal, applying the non-signal and noise gates. Returns null
 * (no trustworthy signal) when the probe was blocked/errored or the page is
 * too unstable to attribute the change.
 *
 * NOTE: this is deliberately conservative — it is the *candidate* detector.
 * Callers must still (a) run a negative control and (b) re-confirm before
 * emitting a finding. See `attributable()` and the scanner call sites.
 */
export function classifyDiff(base: Baseline, probe: ProbeResp | null): DiffSignal {
  if (isNonSignal(probe, base.status)) return null;
  const p = probe!;
  // Status shift is only trustworthy when the baseline agreed on a status.
  if (!base.unstable && p.status !== base.status) return "status-shift";
  const pr = stableRedirect(p.redirect ?? null);
  if (!base.unstable && base.redirect !== null && pr !== base.redirect) return "redirect-shift";
  // Length shift needs a stable baseline and must clear the noise floor.
  if (!base.unstable && exceedsNoise(p.body.length - base.len, base.jitter)) return "len-shift";
  return null;
}

/**
 * Negative-control gate. A signal is only *attributable* to the payload if the
 * control probe (something that should do nothing — a random param name, a
 * benign value) does NOT produce the same signal. If the control fires too,
 * the "signal" is a property of the request in general (URL echo, per-request
 * variance), not of the payload.
 *
 * Returns true iff the real signal is present AND the control is silent.
 */
export function attributable(realSignal: DiffSignal, controlSignal: DiffSignal): boolean {
  if (!realSignal) return false;
  if (controlSignal) return false; // control fired → not attributable
  return true;
}

/**
 * Boolean-blind oracle: given the untouched baseline and the TRUE/FALSE probe
 * responses (each already fetched), decide whether they show conditional
 * evaluation. Requires:
 *   - both probes carry signal (non-empty, not newly-errored),
 *   - TRUE ≈ baseline within the noise floor,
 *   - FALSE clearly differs from BOTH baseline and TRUE, beyond the noise floor.
 * Re-confirmation with a swapped/second pair is the caller's responsibility.
 */
export function booleanBlindHit(base: Baseline, tru: ProbeResp | null, fal: ProbeResp | null): boolean {
  if (base.unstable) return false;
  if (isNonSignal(tru, base.status) || isNonSignal(fal, base.status)) return false;
  const t = tru!, f = fal!;
  // A blocked FALSE probe (different status than baseline) is not "SQL false".
  if (t.status !== base.status || f.status !== base.status) return false;
  const dTF = Math.abs(t.body.length - f.body.length);
  const dTB = Math.abs(t.body.length - base.len);
  const dFB = Math.abs(f.body.length - base.len);
  // TRUE must hug the baseline; FALSE must diverge from both — all relative to
  // the page's own jitter, not a fixed percentage.
  const near = Math.max(base.jitter, 16);
  const far = Math.max(base.jitter * 3, 64);
  return dTB <= near && dTF >= far && dFB >= far;
}

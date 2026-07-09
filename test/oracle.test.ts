/**
 * Differential-oracle tests. These lock in the anti-false-positive rules that
 * a real scan violated: trusting blocked/empty probes, ignoring page jitter,
 * treating rotating redirect nonces as change, and firing without a control.
 */
import { test } from "node:test";
import assert from "node:assert";
import {
  isNonSignal,
  noiseFloor,
  stableRedirect,
  measureBaseline,
  classifyDiff,
  attributable,
  booleanBlindHit,
  exceedsNoise,
  type ProbeResp,
  type Baseline,
} from "../lib/scanners/web/_oracle";

const R = (body: string, status = 200, redirect: string | null = null, latencyMs = 10): ProbeResp => ({
  body,
  status,
  redirect,
  latencyMs,
});

test("isNonSignal: rejects empty / errored / newly-4xx probes", () => {
  assert.strictEqual(isNonSignal(R("", 200), 200), true, "empty body");
  assert.strictEqual(isNonSignal(R("x", 0), 200), true, "transport error");
  assert.strictEqual(isNonSignal(R("blocked", 406), 200), true, "newly 4xx = blocked");
  assert.strictEqual(isNonSignal(R("throttled", 429), 200), true, "rate-limited");
  assert.strictEqual(isNonSignal(R("ok", 200), 200), false, "real 200 body carries signal");
  // If the baseline itself was a 404, a probe 404 is not "newly errored".
  assert.strictEqual(isNonSignal(R("not found", 404), 404), false);
});

test("noiseFloor: largest deviation from median", () => {
  assert.strictEqual(noiseFloor([100, 100, 100]), 0);
  assert.strictEqual(noiseFloor([100, 120, 90]), 20); // median 100, max dev 20
  assert.strictEqual(noiseFloor([1000]), 0); // single sample → unknown → 0
});

test("stableRedirect: strips rotating auth nonces before comparison", () => {
  const a = "https://auth.example.com/login?state=AAA&client_id=x&ui_locales=en";
  const b = "https://auth.example.com/login?state=ZZZ&client_id=x&ui_locales=en";
  assert.strictEqual(stableRedirect(a), stableRedirect(b), "state nonce must not distinguish redirects");
  assert.strictEqual(stableRedirect(a), "https://auth.example.com/login?client_id=x&ui_locales=en");
  assert.strictEqual(stableRedirect(null), null);
});

test("classifyDiff: no signal on an unstable page", async () => {
  // Baselines disagree on length wildly and on status → unstable.
  const base: Baseline = {
    samples: [],
    len: 300000,
    jitter: 27000,
    status: 200,
    redirect: null,
    unstable: true,
  };
  // A 31 KB "shift" is within the noise of a page that jitters 27 KB.
  assert.strictEqual(classifyDiff(base, R("x".repeat(331000), 200)), null);
});

test("classifyDiff: length shift must clear the measured noise floor", () => {
  const base: Baseline = { samples: [], len: 1000, jitter: 200, status: 200, redirect: null, unstable: false };
  // delta 300 < max(64, 200*3=600) → not enough
  assert.strictEqual(classifyDiff(base, R("y".repeat(1300), 200)), null);
  // delta 900 > 600 → len-shift
  assert.strictEqual(classifyDiff(base, R("y".repeat(1900), 200)), "len-shift");
});

test("exceedsNoise: absolute floor and jitter multiple", () => {
  assert.strictEqual(exceedsNoise(50, 0), false); // below absolute floor 64
  assert.strictEqual(exceedsNoise(100, 0), true);
  assert.strictEqual(exceedsNoise(100, 40), false); // below 40*3=120
  assert.strictEqual(exceedsNoise(200, 40), true);
});

test("attributable: control firing kills the signal (URL-echo case)", () => {
  // Real param reflected AND a random control param reflected too → URL echo.
  assert.strictEqual(attributable("len-shift", "len-shift"), false);
  // Real signal present, control silent → attributable.
  assert.strictEqual(attributable("len-shift", null), true);
  assert.strictEqual(attributable(null, null), false);
});

test("booleanBlindHit: rejects a blocked FALSE probe (falLen=0)", () => {
  // The exact shape from the real FP: baseline=true=3024 bytes, false=0 bytes.
  const base: Baseline = { samples: [], len: 3024, jitter: 20, status: 200, redirect: null, unstable: false };
  const tru = R("z".repeat(3024), 200);
  const fal = R("", 200); // blocked / empty — NOT "sql false"
  assert.strictEqual(booleanBlindHit(base, tru, fal), false);
});

test("booleanBlindHit: rejects noise-level divergence on a jittery page", () => {
  const base: Baseline = { samples: [], len: 328882, jitter: 27000, status: 200, redirect: null, unstable: false };
  const tru = R("z".repeat(328882), 200);
  const fal = R("z".repeat(359783), 200); // ~31 KB diff — within 3× jitter (81 KB)
  assert.strictEqual(booleanBlindHit(base, tru, fal), false);
});

test("booleanBlindHit: fires on a clean, stable conditional difference", () => {
  const base: Baseline = { samples: [], len: 5000, jitter: 30, status: 200, redirect: null, unstable: false };
  const tru = R("z".repeat(5000), 200); // == baseline
  const fal = R("z".repeat(1200), 200); // far from both, well beyond jitter
  assert.strictEqual(booleanBlindHit(base, tru, fal), true);
});

test("measureBaseline: flags an unstable page and returns null when blocked", async () => {
  let i = 0;
  const varying = await measureBaseline(async () => {
    i++;
    return R("x".repeat(i === 1 ? 1000 : 5000), i === 1 ? 200 : 302, "https://x/next");
  });
  assert.ok(varying);
  assert.strictEqual(varying!.unstable, true, "differing status across samples → unstable");

  const blocked = await measureBaseline(async () => R("", 200));
  assert.strictEqual(blocked, null, "cannot baseline a blocked page");
});

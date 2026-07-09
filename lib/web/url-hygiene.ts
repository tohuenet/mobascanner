/**
 * URL hygiene — the gate that keeps synthetic, non-fetchable "URLs" out of the
 * crawl frontier and the DiscoveryBus.
 *
 * Why this exists: robots.txt `Disallow:` lines are *match patterns*, not
 * URLs. They routinely carry glob metacharacters (`*`), an end-of-URL anchor
 * (`$`), and bare path-prefix markers (a trailing `?`). Feeding them to
 * `fetch()` produces a synthetic 404 / redirect whose body is unstable from
 * request to request — and that instability is exactly what fools the
 * differential detectors (param-miner, sqli, query-fuzzer) into emitting
 * false positives. One real scan against a CDN-fronted site turned
 * `Disallow: /*?format=json` and `Disallow: /blocks?` into a "hidden
 * parameter" flood and several "boolean-blind SQLi" criticals.
 *
 * The rule: a URL is only probeable if it could plausibly be a single, real,
 * fetchable resource. Anything that looks like a pattern is dropped at the
 * source.
 */

/** Characters that never appear unencoded in a real, fetchable path/query but
 *  are common in robots patterns and copy-paste noise. */
const CONTROL_OR_WS = /[\s<>{}|\\^`]/;

/**
 * True iff `raw` is a concrete, fetchable http(s) URL rather than a match
 * pattern or malformed string. Used at every point a URL enters the crawl
 * frontier or the DiscoveryBus.
 */
export function isProbeableUrl(raw: string): boolean {
  if (typeof raw !== "string" || !raw) return false;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;

  // Glob wildcard — robots `Disallow: /*/followers`, `/*?format=json`.
  if (u.pathname.includes("*")) return false;
  // robots end-of-URL anchor — `Disallow: /x/info$`.
  if (/\$(?:\/|$)/.test(u.pathname)) return false;
  // Bare path-prefix marker — robots `Disallow: /api?`, `/blocks?`. The WHATWG
  // parser keeps the trailing `?` in href while leaving search empty.
  if (raw.trimEnd().endsWith("?")) return false;
  // Whitespace / angle-bracket / control noise: not a real URL.
  if (CONTROL_OR_WS.test(raw)) return false;

  return true;
}

// Second-level labels that are really part of a multi-part public suffix
// (`example.co.uk`, `example.com.au`). Not a full Public Suffix List, but it
// covers the cases that matter for same-site classification without a dep.
const MULTI_PART_SLD = new Set(["co", "com", "org", "net", "gov", "edu", "ac", "gob", "mil", "or", "ne"]);

/**
 * Best-effort registrable domain (eTLD+1) of a hostname, used to decide whether
 * two hosts are the "same site" (e.g. `cdn.example.com` vs `www.example.com`).
 * Heuristic, not PSL-backed — good enough for first-vs-third-party grouping.
 */
export function registrableDomain(hostname: string): string {
  const labels = hostname.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const last2 = labels.slice(-2);
  if (MULTI_PART_SLD.has(last2[0])) return labels.slice(-3).join(".");
  return last2.join(".");
}

/** True iff two hosts share a registrable domain (same-site). */
export function sameSite(hostA: string, hostB: string): boolean {
  return registrableDomain(hostA) === registrableDomain(hostB);
}

/**
 * Filter a list of candidate URLs down to the probeable ones, preserving order
 * and de-duplicating. Convenience for scanners that read a batch (e.g.
 * query-fuzzer collecting SiteMap URLs).
 */
export function keepProbeableUrls(urls: Iterable<string>): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const u of urls) {
    if (seen.has(u) || !isProbeableUrl(u)) continue;
    seen.add(u);
    out.push(u);
  }
  return out;
}

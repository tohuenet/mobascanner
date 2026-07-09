/**
 * Query-string fuzzer — applies the same XSS / SQLi / LFI / cmd-injection
 * probe set as form-fuzzer, but to URL query parameters instead of form
 * inputs.
 *
 * Static run: iterates URLs from the SiteMap that already carry a query
 *   string (or whose pages had reflective query keys).
 * Consumer: any "url" item published into the DiscoveryBus that has a query
 *   string gets fuzzed on the fly — so a URL the SPA crawler captured via
 *   XHR-with-params, or a redirect target after a form submit, still gets
 *   probed without waiting for a fresh scan.
 *
 * Discovery feedback: each probe submit's final URL (after redirects) is
 * fed back into the bus so chained behavior (eg /search?q=… → /redirect?next=…
 * → /admin) gets explored automatically.
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner, type ScanContext, type DiscoveredItem } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";
import { buildProbes, effectiveRule, type Probe } from "./_probes";

/** Per-scan BrowsingSession cache. Shared between run() and consume() so
 *  any cookies the form-fuzzer's benign baseline accrued (eg session after
 *  /login post) carry into query-fuzz probes of authenticated URLs. */
const sessions = new Map<string, BrowsingSession>();

function getSession(ctx: ScanContext): BrowsingSession {
  const existing = sessions.get(ctx.scanId);
  if (existing) return existing;
  const seed = safeUrl(ctx.target.value);
  const origin = seed?.origin ?? ctx.target.value;
  const fresh = new BrowsingSession(origin, {
    ...(ctx.target.auth?.headers ?? {}),
    ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
  });
  sessions.set(ctx.scanId, fresh);
  return fresh;
}

function discoverDestination(
  fromUrl: string,
  r: { redirectChain: string[]; finalUrl: string },
  ctx: ScanContext,
) {
  let fromHost = "";
  try { fromHost = new URL(fromUrl).host; } catch { /* skip */ }
  for (const hop of r.redirectChain) {
    try {
      if (fromHost && new URL(hop).host !== fromHost) continue;
      ctx.discover({
        kind: "url",
        url: hop,
        source: { scannerId: "web.query-fuzzer", via: "query-redirect", parentUrl: fromUrl },
      });
    } catch { /* skip */ }
  }
  if (r.finalUrl && r.finalUrl !== fromUrl) {
    try {
      if (!fromHost || new URL(r.finalUrl).host === fromHost) {
        ctx.discover({
          kind: "url",
          url: r.finalUrl,
          source: { scannerId: "web.query-fuzzer", via: "query-landing", parentUrl: fromUrl },
        });
      }
    } catch { /* skip */ }
  }
}

/** Probe each query param on `url` with every probe, emit findings, feed
 *  redirect destinations back into the bus. Returns the number of submits. */
async function fuzzUrl(
  rawUrl: string,
  session: BrowsingSession,
  ctx: ScanContext,
  probes: Probe[],
  canary: string,
): Promise<number> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return 0;
  }
  const paramKeys = [...parsed.searchParams.keys()];
  if (paramKeys.length === 0) return 0;

  let count = 0;
  for (const key of paramKeys) {
    for (const p of probes) {
      if (ctx.signal.aborted) return count;
      const probed = new URL(parsed.toString());
      probed.searchParams.set(key, p.payload);
      const t0 = Date.now();
      let body = "";
      let status = 0;
      let contentType = "";
      let redirectChain: string[] = [];
      let finalUrl = "";
      try {
        const r = await session.fetch(probed.toString(), { method: "GET", signal: ctx.signal });
        body = r.body;
        status = r.res.status;
        contentType = r.res.headers.get("content-type") ?? "";
        redirectChain = r.redirectChain;
        finalUrl = r.finalUrl;
      } catch {
        continue;
      }
      count += 1;
      discoverDestination(probed.toString(), { redirectChain, finalUrl }, ctx);

      const hit = p.detect({ body, latencyMs: Date.now() - t0, contentType }, canary);
      if (!hit) continue;
      const rule = effectiveRule(p.rule, hit);
      const labelPrefix = rule === "reflection/json-echo" ? "PARAM REFLECTION" : rule.toUpperCase();
      await ctx.emit(draft({
        severity: hit.severity,
        confidence: p.rule.startsWith("sqli/time") ? "medium" : "high",
        title: `${labelPrefix} on query param "${key}" (${parsed.pathname})`,
        description: `Probe payload: ${truncate(p.payload, 80)}\n\n→ ${hit.reason}`,
        ruleId: rule,
        cwe: hit.cwe,
        owasp: hit.owasp,
        location: { url: probed.toString(), snippet: key },
        evidence: { param: key, payload: p.payload, status, snippet: truncate(body, 400) },
        remediation: hit.remediation,
      }));
    }
  }
  return count;
}

/** Cap the static-phase work — the consumer phase can pick up the long tail. */
const STATIC_URL_CAP = 50;

/** Per-scan dedupe so consume() doesn't re-fuzz a URL that run() already
 *  processed (the crawler publishes URLs into the bus that overlap with
 *  ones we read from the SiteMap). */
const fuzzedUrls = new Map<string, Set<string>>();

function urlCanonicalKey(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    const sortedQ = [...u.searchParams.keys()].sort().join(",");
    return `${u.protocol}//${u.host}${u.pathname}?${sortedQ}`;
  } catch {
    return rawUrl;
  }
}

function markFuzzed(scanId: string, rawUrl: string): void {
  let s = fuzzedUrls.get(scanId);
  if (!s) {
    s = new Set();
    fuzzedUrls.set(scanId, s);
  }
  s.add(urlCanonicalKey(rawUrl));
}

function alreadyFuzzed(scanId: string, rawUrl: string): boolean {
  return fuzzedUrls.get(scanId)?.has(urlCanonicalKey(rawUrl)) ?? false;
}

export const queryFuzzerScanner: Scanner = {
  id: "web.query-fuzzer",
  name: "Query-Param Fuzzer",
  kind: "web",
  description:
    "Replaces each URL query parameter with XSS/SQLi/LFI/cmd-injection payloads and checks the response. Subscribes to the DiscoveryBus so URLs surfaced mid-scan (SPA XHRs, form redirects) get fuzzed too.",
  defaultEnabled: false,
  consumes: ["url"],

  async tool() {
    return {
      id: "web.query-fuzzer",
      name: "Query-Param Fuzzer",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Built-in URL query-string injection fuzzer.",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) {
      await ctx.log("error", "invalid URL");
      return;
    }
    const session = getSession(ctx);
    const canary = "MOBA" + randomBytes(4).toString("hex");
    const probes = buildProbes(canary);

    const candidates = new Set<string>();
    // Always include the seed URL if it has a query string.
    if (seed.search) candidates.add(seed.toString());

    const map = await loadSiteMap(ctx.scanId);
    if (map) {
      // Pages with explicit query strings or reflective keys are the highest
      // signal — fuzz those first.
      for (const p of map.pages) {
        try {
          const u = new URL(p.url);
          if (u.search) candidates.add(p.url);
          else if (p.reflectedQueryKeys && p.reflectedQueryKeys.length > 0) candidates.add(p.url);
        } catch {
          /* skip malformed page url */
        }
      }
    }

    const list = [...candidates].slice(0, STATIC_URL_CAP);
    if (!list.length) {
      await ctx.log("info", "no URLs with query params in SiteMap — will still consume dynamic URLs");
      await ctx.progress(1, "skipped");
      return;
    }

    let done = 0;
    let submissions = 0;
    for (const u of list) {
      if (ctx.signal.aborted) break;
      markFuzzed(ctx.scanId, u);
      submissions += await fuzzUrl(u, session, ctx, probes, canary);
      done += 1;
      await ctx.progress(done / list.length, `${done}/${list.length}, ${submissions} probes`);
    }
    await ctx.progress(1, `${submissions} probes across ${done} URL(s)`);
  },

  async consume(item: DiscoveredItem, ctx: ScanContext) {
    if (item.kind !== "url") return;
    let parsed: URL;
    try {
      parsed = new URL(item.url);
    } catch {
      return;
    }
    if (![...parsed.searchParams.keys()].length) return; // no params, nothing to fuzz
    if (alreadyFuzzed(ctx.scanId, item.url)) return;
    markFuzzed(ctx.scanId, item.url);
    const session = getSession(ctx);
    const canary = "MOBA" + randomBytes(4).toString("hex");
    const probes = buildProbes(canary);
    const submissions = await fuzzUrl(item.url, session, ctx, probes, canary);
    if (submissions > 0) {
      await ctx.log("info", `consumed late URL ${item.url} — ${submissions} probes`);
    }
  },
};

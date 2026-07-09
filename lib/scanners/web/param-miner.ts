/**
 * Parameter miner — discovers hidden GET parameters that the application
 * accepts but doesn't advertise. Inspired by Burp's `param-miner` extension.
 *
 * Method:
 *   1. Send a baseline request (no extra params) and record content length +
 *      header set + body fingerprint.
 *   2. For each candidate parameter name from a curated wordlist, send the
 *      same URL with `?name=CANARY`. If the response differs from baseline
 *      in length, redirect, header set, OR contains the canary in the body,
 *      that parameter is "alive".
 *
 * Wordlist is curated to ~120 highest-signal names (ids, debug flags, file
 * loaders, callbacks, redirects). For exhaustive coverage, install ffuf.
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { isProbeableUrl } from "../../web/url-hygiene";
import { loadSiteMap, interestingPages } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";
import { measureBaseline, classifyDiff, type ProbeResp } from "./_oracle";

const PARAMS = [
  // Generic ids
  "id", "uid", "user", "user_id", "userid", "account", "account_id", "uuid",
  "session", "sessionid", "session_id", "sid", "auth", "token", "access_token",
  // Pagination / sorting
  "page", "limit", "offset", "size", "per_page", "skip", "take", "sort", "order",
  // File / path manipulation (LFI surface)
  "file", "filename", "path", "name", "page", "view", "template", "include",
  "src", "source", "doc", "document", "image", "img", "uri", "url",
  // Redirects (open-redirect surface)
  "redirect", "redirect_uri", "return", "returnTo", "return_to", "url",
  "next", "continue", "callback", "cb", "destination", "dest", "rurl",
  // Debug / test
  "debug", "test", "trace", "verbose", "log", "logging", "dev", "admin",
  "show", "hide", "preview", "draft", "internal",
  // SSRF surface
  "host", "domain", "fetch", "proxy", "target",
  // SQL-y
  "query", "search", "q", "filter", "where", "select",
  // Format / output
  "format", "output", "lang", "locale", "type", "kind", "mode",
  // Auth-y
  "role", "permission", "scope", "is_admin", "isAdmin",
  // Webhooks
  "webhook", "webhook_url", "callback_url", "notify_url",
  // Misc
  "key", "api_key", "apikey", "secret", "password", "pass",
  "csrf_token", "xsrf", "_token", "ref", "tag", "category",
  "version", "v", "ver", "build",
];

export const paramMinerScanner: Scanner = {
  id: "web.param-miner",
  name: "Hidden Parameter Miner",
  kind: "web",
  description: "Probes ~120 candidate parameter names against each high-interest URL. Discovers hidden GET params that the app accepts but doesn't advertise (debug flags, file loaders, redirect targets, etc.).",
  defaultEnabled: false,

  async tool() {
    return {
      id: "web.param-miner", name: "Parameter Miner", kind: "web", backend: "builtin", status: "available",
      description: "Hidden parameter discovery via wordlist diff.",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    let urls: string[];
    if (map) {
      // Sort by interest score descending so we cover the highest-signal URLs
      // first, then take a wider slice — feature-flag params are often on
      // boring routes like /info that only score 0.3-0.4.
      urls = interestingPages(map, 0.3)
        .sort((a, b) => (b.interestScore ?? 0) - (a.interestScore ?? 0))
        .map((p) => p.url)
        .slice(0, Math.min(Number(ctx.options.maxUrls) || 20, 50));
      if (!urls.length) urls = [seed.toString()];
    } else {
      urls = [seed.toString()];
    }

    const session = new BrowsingSession(seed.origin, {
      ...(ctx.target.auth?.headers ?? {}),
      ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
    });

    // One probe = set `name=value` on the URL and read the response.
    const probe = async (baseUrl: URL, name: string, value: string): Promise<ProbeResp | null> => {
      const probeUrl = new URL(baseUrl.toString());
      probeUrl.searchParams.set(name, value);
      try {
        const r = await session.fetch(probeUrl.toString(), { signal: ctx.signal });
        const redirect = r.redirectChain.length ? r.redirectChain[r.redirectChain.length - 1] : null;
        return { status: r.res.status, body: r.body, latencyMs: 0, redirect };
      } catch {
        return null;
      }
    };

    const total = urls.length * PARAMS.length;
    let done = 0;

    for (const u of urls) {
      if (ctx.signal.aborted) break;
      if (!isProbeableUrl(u)) continue; // never mine a synthetic / pattern URL
      const baseUrl = new URL(u);

      // Two baselines establish the page's jitter + determinism. A page whose
      // untouched responses already disagree on status / redirect (auth
      // redirects, A/B buckets) cannot attribute a per-param change, so skip it.
      const base = await measureBaseline(async () => {
        try {
          const r = await session.fetch(baseUrl.toString(), { signal: ctx.signal });
          const redirect = r.redirectChain.length ? r.redirectChain[r.redirectChain.length - 1] : null;
          return { status: r.res.status, body: r.body, latencyMs: 0, redirect } as ProbeResp;
        } catch { return null; }
      }, 2);
      done += 2;
      if (!base) continue;
      if (base.unstable) {
        await ctx.log("info", `${u}: non-deterministic baseline — skipping param-mining`);
        continue;
      }

      // NEGATIVE CONTROL — a parameter name the app cannot possibly handle. If
      // this bogus param reflects its canary or shifts the response, the app
      // echoes / reacts to ANY parameter, so per-param signals are NOT
      // attributable to the name. This single check kills the URL-echo flood
      // (109 "hidden params" on one page all reflecting the request URL).
      const controlName = "zzq" + randomBytes(4).toString("hex");
      const controlCanary = "moba" + randomBytes(3).toString("hex");
      const controlResp = await probe(baseUrl, controlName, controlCanary);
      done += 1;
      const echoProne = controlResp ? controlResp.body.includes(controlCanary) : false;
      const shiftProne = controlResp ? classifyDiff(base, controlResp) !== null : false;
      if (echoProne && shiftProne) {
        await ctx.log("info", `${u}: reacts to arbitrary params (URL echo) — suppressing param-mining`);
        continue;
      }

      const signalFor = (resp: ProbeResp | null, canary: string): string | null => {
        if (!resp) return null;
        if (!echoProne && resp.body.includes(canary)) return "canary-reflected";
        if (!shiftProne) { const s = classifyDiff(base, resp); if (s) return s; }
        return null;
      };

      const alive: { name: string; signal: string; lenDelta: number; bodySnippet: string }[] = [];
      for (const name of PARAMS) {
        if (ctx.signal.aborted) break;
        if (baseUrl.searchParams.has(name)) continue;
        const canary = "moba" + randomBytes(3).toString("hex");
        const resp = await probe(baseUrl, name, canary);
        done += 1;
        if (done % 30 === 0) await ctx.progress(Math.min(done / total, 0.99), `${u} +${name}`);
        const signal = signalFor(resp, canary);
        if (!signal) continue;
        // RE-CONFIRM — the signal must reproduce on a fresh, differently-seeded
        // probe. Drops one-shot flukes from transient variance.
        const canary2 = "moba" + randomBytes(3).toString("hex");
        const resp2 = await probe(baseUrl, name, canary2);
        done += 1;
        if (signalFor(resp2, canary2) !== signal) continue;
        alive.push({ name, signal, lenDelta: (resp!.body.length - base.len), bodySnippet: truncate(resp!.body, 200) });
      }

      if (alive.length === 0) continue;

      // Plausibility backstop: a page that "accepts" a large fraction of a
      // generic wordlist is unstable in a way the control missed, not a trove
      // of hidden params. Suppress rather than flood.
      if (alive.length > Math.max(6, PARAMS.length * 0.25)) {
        await ctx.log("info", `${u}: ${alive.length}/${PARAMS.length} params 'accepted' — implausible, suppressing`);
        continue;
      }

      for (const a of alive) {
        const reflected = a.signal === "canary-reflected";
        await ctx.emit(draft({
          severity: reflected ? "medium" : "low",
          confidence: reflected ? "high" : "medium",
          title: `Hidden parameter accepted: "${a.name}" (${a.signal}) on ${u}`,
          description: `The app reacts to a parameter "${a.name}" not visible in any link/form. The reaction reproduced on a re-probe while a random control parameter stayed silent (${a.signal}; len Δ ${a.lenDelta}).${reflected ? " The value is reflected in the response — worth fuzzing for XSS / open-redirect with the injection scanners." : ""}`,
          ruleId: `param-miner/${a.signal}`,
          cwe: ["CWE-200"],
          owasp: ["A05:2021"],
          location: { url: u, snippet: `?${a.name}=` },
          evidence: {
            baseline: { len: base.len, status: base.status, jitter: base.jitter },
            control: { name: controlName, reflected: echoProne, shifted: shiftProne },
            probe: { signal: a.signal, lenDelta: a.lenDelta, reconfirmed: true, snippet: a.bodySnippet },
          },
          remediation: "Audit what this parameter does. If it's a debug/feature flag, gate it behind auth or remove it. If it's a redirect/file loader, validate the value against an allow-list.",
        }));
      }
    }
    await ctx.progress(1, `${done} param probes`);
  },
};

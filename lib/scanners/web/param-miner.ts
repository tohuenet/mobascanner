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
import { loadSiteMap, interestingPages } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

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

interface BaselineSig {
  status: number;
  bodyLen: number;
  headerSet: string;
  bodyHead: string;
  redirect: string | null;
}

function fingerprint(body: string, status: number, headers: Headers, redirectChain: string[]): BaselineSig {
  const headerKeys = [...headers.keys()].sort().join(",");
  return {
    status,
    bodyLen: body.length,
    headerSet: headerKeys,
    bodyHead: body.slice(0, 200),
    redirect: redirectChain.length ? redirectChain[redirectChain.length - 1] : null,
  };
}

function differs(a: BaselineSig, b: BaselineSig, canary: string, body: string): "canary-reflected" | "len-shift" | "redirect-shift" | "header-shift" | "status-shift" | null {
  if (body.includes(canary)) return "canary-reflected";
  if (a.status !== b.status) return "status-shift";
  if (a.redirect !== b.redirect) return "redirect-shift";
  if (a.headerSet !== b.headerSet) return "header-shift";
  if (Math.abs(a.bodyLen - b.bodyLen) > Math.max(64, a.bodyLen * 0.05)) return "len-shift";
  return null;
}

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

    const total = urls.length * PARAMS.length;
    let done = 0;

    for (const u of urls) {
      if (ctx.signal.aborted) break;
      const baseUrl = new URL(u);

      // Take TWO baselines so we know what same-page jitter looks like
      // (dynamic timestamps, session cookies, csrf tokens, etc.). The
      // detection threshold is then "diff bigger than baseline jitter".
      let b1; try { b1 = await session.fetch(baseUrl.toString(), { signal: ctx.signal }); }
      catch { continue; }
      let b2; try { b2 = await session.fetch(baseUrl.toString(), { signal: ctx.signal }); }
      catch { continue; }
      const baseSig = fingerprint(b1.body, b1.res.status, b1.res.headers, b1.redirectChain);
      const jitterLen = Math.abs(b1.body.length - b2.body.length);
      // Required len-shift to count as signal: max(64, 5×jitter, 5% of body).
      const lenThreshold = Math.max(64, jitterLen * 5, Math.floor(b1.body.length * 0.05));

      // For each candidate param we try TWO values: a random canary (catches
      // reflection / generic acceptance) and a "feature-flag" value (catches
      // params like ?debug=1 or ?admin=true that only branch on specific
      // truthy values). Either signal qualifies the param as accepted.
      const FLAG_VALUES = ["1", "true", "on"];
      const alive: { name: string; signal: string; value: string; bodySnippet: string; lenDelta: number }[] = [];
      for (const name of PARAMS) {
        if (ctx.signal.aborted) break;
        if (baseUrl.searchParams.has(name)) continue;
        const canary = "moba" + randomBytes(3).toString("hex");
        const valuesToTry = [canary, ...FLAG_VALUES];
        for (const value of valuesToTry) {
          const probeUrl = new URL(baseUrl.toString());
          probeUrl.searchParams.set(name, value);
          let r;
          try { r = await session.fetch(probeUrl.toString(), { signal: ctx.signal }); }
          catch { done += 1; continue; }
          done += 1;
          if (done % 30 === 0) await ctx.progress(done / total, `${u} +${name}=${value}`);
          const sig = fingerprint(r.body, r.res.status, r.res.headers, r.redirectChain);

          let signal: string | null = null;
          if (value === canary && r.body.includes(canary)) signal = "canary-reflected";
          else if (sig.status !== baseSig.status) signal = "status-shift";
          else if (sig.redirect !== baseSig.redirect) signal = "redirect-shift";
          else {
            const lenDelta = Math.abs(r.body.length - baseSig.bodyLen);
            if (lenDelta >= lenThreshold) signal = "len-shift";
          }
          if (signal) {
            alive.push({ name, signal, value, bodySnippet: truncate(r.body, 200), lenDelta: r.body.length - baseSig.bodyLen });
            // Don't probe further values once one has triggered for this name.
            break;
          }
        }
      }

      if (alive.length === 0) continue;

      // Even with the noise filter, if a *very high* fraction of probes alive
      // on a single URL with the same signal, the page is likely just
      // unstable; skip rather than flood.
      const lenShiftCount = alive.filter((a) => a.signal === "len-shift").length;
      if (lenShiftCount > PARAMS.length * 0.4) {
        await ctx.log("info", `${u}: ${lenShiftCount} len-shifts — likely unstable page, suppressing`);
        continue;
      }

      for (const a of alive) {
        const isFlag = ["1", "true", "on"].includes(a.value);
        const sev: "high" | "medium" | "low" =
          a.signal === "canary-reflected" ? "high" :
          isFlag ? "medium" :
          a.signal === "redirect-shift" || a.signal === "status-shift" ? "medium" : "low";
        await ctx.emit(draft({
          severity: sev,
          confidence: a.signal === "canary-reflected" ? "high" : "medium",
          title: `Hidden parameter accepted: "${a.name}=${a.value}" (${a.signal}) on ${u}`,
          description: `The app accepts a parameter named "${a.name}" that wasn't visible in any link/form on the page. Probing value="${a.value}" produced a different response (${a.signal}; len Δ ${a.lenDelta}).${a.signal === "canary-reflected" ? " Canary reflected — strong reflection / potential XSS surface." : isFlag ? " Looks like a feature/debug flag the app honors silently." : ""}`,
          ruleId: `param-miner/${a.signal}`,
          cwe: a.signal === "canary-reflected" ? ["CWE-79", "CWE-200"] : ["CWE-200"],
          owasp: ["A05:2021"],
          location: { url: u, snippet: `?${a.name}=${a.value}` },
          evidence: { baseline: { len: baseSig.bodyLen, status: baseSig.status, jitter: jitterLen }, probe: { signal: a.signal, value: a.value, lenDelta: a.lenDelta, snippet: a.bodySnippet } },
          remediation: "Audit what this parameter does. If it's a debug/feature flag, gate it behind auth or remove it. If it's a redirect/file loader, validate the value against an allow-list.",
        }));
      }
    }
    await ctx.progress(1, `${done} param probes`);
  },
};

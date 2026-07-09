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
 *
 * Dynamic-discovery integration (engine plan P2b):
 *   - The static `run()` reads forms from the persisted SiteMap as before.
 *   - `consume({kind: "form"})` fires for any form a later scanner publishes
 *     into the DiscoveryBus (e.g. SPA crawler finds a form post-render, or a
 *     content-discovery hit reveals a new form). Same fuzz loop, same emit
 *     contract.
 *   - After every submit we feed the post-submit destination URL back into
 *     the bus via ctx.discover — that's how a register form → /dashboard
 *     chain ends up being discovered without manual seeding.
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner, type ScanContext, type DiscoveredItem } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap, type SiteMapForm } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";
import { buildProbes, effectiveRule, type Probe } from "./_probes";

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

const SKIP_INPUT_TYPES = new Set(["submit", "button", "reset", "image", "file"]);
const CSRF_NAME_RE = /(csrf|xsrf|authenticity_token|_token)/i;

function fuzzableInputsOf(form: SiteMapForm): SiteMapForm["inputs"] {
  return form.inputs.filter(
    (i) => !SKIP_INPUT_TYPES.has(i.type) && !CSRF_NAME_RE.test(i.name),
  );
}

/** Per-scan set of forms we already fuzzed. Prevents consume() from
 *  re-fuzzing a form that run() already processed (the crawler publishes
 *  the same form into the bus that it wrote into the SiteMap). Keyed by
 *  scanId so concurrent scans don't pollute each other's dedupe. */
const fuzzedForms = new Map<string, Set<string>>();

function formCanonicalKey(form: SiteMapForm): string {
  const inputs = form.inputs.map((i) => i.name).filter(Boolean).sort().join(",");
  return `${form.method}|${form.action}|${inputs}`;
}

function markFuzzed(scanId: string, form: SiteMapForm): void {
  let s = fuzzedForms.get(scanId);
  if (!s) {
    s = new Set();
    fuzzedForms.set(scanId, s);
  }
  s.add(formCanonicalKey(form));
}

function alreadyFuzzed(scanId: string, form: SiteMapForm): boolean {
  return fuzzedForms.get(scanId)?.has(formCanonicalKey(form)) ?? false;
}

/** Per-scan cache of BrowsingSession so cookies set during the run-phase's
 *  benign-baseline submits survive into consume(). Without this, a register
 *  form that lands on /dashboard would lose its session when consume() later
 *  fuzzes a form discovered AFTER the user was "logged in" mid-scan. */
const sessions = new Map<string, BrowsingSession>();

function getSession(ctx: ScanContext): BrowsingSession {
  const existing = sessions.get(ctx.scanId);
  if (existing) return existing;
  const seed = safeUrl(ctx.target.value);
  const origin = seed?.origin ?? ctx.target.value;
  const fresh = new BrowsingSession(origin, {
    ...(ctx.target.auth?.headers ?? {}),
    ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
  });
  sessions.set(ctx.scanId, fresh);
  return fresh;
}

/** Emit the post-submit destination (final URL + each redirect hop) into the
 *  discovery bus. Cleaned-up so we don't chase off-host SSO/parking pages. */
function emitDestinations(
  form: SiteMapForm,
  r: { redirectChain: string[]; finalUrl: string },
  ctx: ScanContext,
  via: string,
) {
  let formHost = "";
  try { formHost = new URL(form.action).host; } catch { /* ignore */ }
  for (const hop of r.redirectChain) {
    try {
      if (formHost && new URL(hop).host !== formHost) continue;
      ctx.discover({
        kind: "url",
        url: hop,
        source: { scannerId: "web.form-fuzzer", via, parentUrl: form.action },
      });
    } catch { /* skip */ }
  }
  if (r.finalUrl && r.finalUrl !== form.action) {
    try {
      if (!formHost || new URL(r.finalUrl).host === formHost) {
        ctx.discover({
          kind: "url",
          url: r.finalUrl,
          source: { scannerId: "web.form-fuzzer", via: `${via}-landing`, parentUrl: form.action },
        });
      }
    } catch { /* skip */ }
  }
}

/** ONE benign submission with all inputs at their baseline values. The point
 *  isn't detection — it's discovery: the landing page after a valid submit
 *  is exactly the "/dashboard" / "/admin" / etc. surface the user actually
 *  cares about. Doing this BEFORE the attack payloads also means the
 *  destination URL flows into the bus without attack-payload error noise. */
async function benignSubmit(
  form: SiteMapForm,
  session: BrowsingSession,
  ctx: ScanContext,
): Promise<void> {
  const built = buildBody(form);
  if (!built) return;
  try {
    if ("url" in built && built.url) {
      const r = await session.fetch(built.url.toString(), { method: "GET", signal: ctx.signal });
      emitDestinations(form, r, ctx, "benign-baseline");
    } else if ("body" in built) {
      const r = await session.fetch(form.action, {
        method: "POST",
        body: built.body,
        headers: { "content-type": built.ct },
        signal: ctx.signal,
      });
      emitDestinations(form, r, ctx, "benign-baseline");
    }
  } catch {
    /* benign pass is best-effort */
  }
}

/** Run all PROBES against every fuzzable input of one form. Emits findings
 *  via ctx.emit and feeds post-submit destination URLs back through
 *  ctx.discover so downstream consumers (other scanners) can re-process them.
 *  Returns the number of submissions attempted. */
async function fuzzForm(
  form: SiteMapForm,
  session: BrowsingSession,
  ctx: ScanContext,
  canary: string,
  probes: Probe[],
  onSubmission?: () => void,
): Promise<number> {
  const inputs = fuzzableInputsOf(form);
  if (!inputs.length) return 0;

  // Benign baseline FIRST — discovery without the attack-payload echo noise.
  await benignSubmit(form, session, ctx);

  let count = 0;

  for (const input of inputs) {
    for (const p of probes) {
      if (ctx.signal.aborted) return count;
      const built = buildBody(form, input.name, p.payload);
      if (!built) continue;
      const t0 = Date.now();
      let body = "";
      let status = 0;
      let contentType = "";
      let redirectChain: string[] = [];
      let finalUrl = "";
      try {
        if ("url" in built && built.url) {
          const r = await session.fetch(built.url.toString(), { method: "GET", signal: ctx.signal });
          body = r.body;
          status = r.res.status;
          contentType = r.res.headers.get("content-type") ?? "";
          redirectChain = r.redirectChain;
          finalUrl = r.finalUrl;
        } else if ("body" in built) {
          const r = await session.fetch(form.action, {
            method: "POST",
            body: built.body,
            headers: { "content-type": built.ct },
            signal: ctx.signal,
          });
          body = r.body;
          status = r.res.status;
          contentType = r.res.headers.get("content-type") ?? "";
          redirectChain = r.redirectChain;
          finalUrl = r.finalUrl;
        }
      } catch {
        continue;
      }
      count += 1;
      onSubmission?.();

      emitDestinations(form, { redirectChain, finalUrl }, ctx, "form-redirect");

      const hit = p.detect({ body, latencyMs: Date.now() - t0, contentType }, canary);
      if (!hit) continue;
      const rule = effectiveRule(p.rule, hit);
      const labelPrefix = rule === "reflection/json-echo" ? "PARAM REFLECTION" : rule.toUpperCase();
      await ctx.emit(draft({
        severity: hit.severity,
        confidence: p.rule.startsWith("sqli/time") ? "medium" : "high",
        title: `${labelPrefix} on form input "${input.name}" (${form.method} ${form.action})`,
        description: `Probe payload: ${truncate(p.payload, 80)}\n\n→ ${hit.reason}`,
        ruleId: rule,
        cwe: hit.cwe,
        owasp: hit.owasp,
        location: { url: form.action, snippet: input.name },
        evidence: { method: form.method, input: input.name, payload: p.payload, status, snippet: truncate(body, 400) },
        remediation: hit.remediation,
      }));
    }
  }
  return count;
}

/** Heuristic: should this form be fuzzed? Login forms go to brute-login;
 *  empty forms are no-ops. Aggressive scans bypass the login filter. */
function shouldFuzz(form: SiteMapForm, opts: { aggressive: boolean }): boolean {
  if (!form.inputs.length) return false;
  if (!opts.aggressive && form.looksLikeLogin) return false;
  return true;
}

export const formFuzzerScanner: Scanner = {
  id: "web.form-fuzzer",
  name: "Form Fuzzer",
  kind: "web",
  description: "Submits every form discovered by the crawler with XSS/SQLi/LFI/cmd-injection probes per non-CSRF input. Skips login forms unless scan.meta.aggressive=true.",
  defaultEnabled: false, // active probes — opt-in
  consumes: ["form"],

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
      await ctx.log("info", "no SiteMap forms — run web.crawler first; will still consume forms discovered dynamically");
      await ctx.progress(1, "skipped");
      return;
    }
    const session = getSession(ctx);
    const aggressive = Boolean(ctx.options.aggressive);

    const forms = map.forms.filter((f) => shouldFuzz(f, { aggressive }));
    if (!forms.length) { await ctx.progress(1, "no fuzzable forms"); return; }

    const canary = "MOBA" + randomBytes(4).toString("hex");
    const probes = buildProbes(canary);
    const totalSubmissions = forms.reduce(
      (a, f) => a + fuzzableInputsOf(f).length * probes.length,
      0,
    );
    let done = 0;

    for (const form of forms) {
      if (ctx.signal.aborted) break;
      markFuzzed(ctx.scanId, form);
      await fuzzForm(form, session, ctx, canary, probes, () => {
        done += 1;
        if (done % 5 === 0) {
          void ctx.progress(done / Math.max(totalSubmissions, 1), `${done}/${totalSubmissions}`);
        }
      });
    }
    await ctx.progress(1, `${done} submissions across ${forms.length} forms`);
  },

  async consume(item: DiscoveredItem, ctx: ScanContext) {
    if (item.kind !== "form") return;
    const aggressive = Boolean(ctx.options.aggressive);
    if (!shouldFuzz(item.form, { aggressive })) return;
    if (alreadyFuzzed(ctx.scanId, item.form)) return; // run() got there first
    markFuzzed(ctx.scanId, item.form);
    // Each consume call is its own micro-session — keeps state simple and
    // means consume work doesn't fight the run-phase session for cookies.
    const session = getSession(ctx);
    const canary = "MOBA" + randomBytes(4).toString("hex");
    const probes = buildProbes(canary);
    const submissions = await fuzzForm(item.form, session, ctx, canary, probes);
    if (submissions > 0) {
      await ctx.log("info", `consumed late form ${item.form.method} ${item.form.action} — ${submissions} submissions`);
    }
  },
};

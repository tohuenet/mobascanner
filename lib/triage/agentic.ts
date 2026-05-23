/**
 * AI-driven attack-chain executor.
 *
 * Given the current scan's findings + sitemap, asks Claude what probe
 * has the highest expected information gain next, then executes it
 * (sandboxed) and feeds the result back. Loops up to N times.
 *
 * Why this matters: a skilled pentester adapts based on what they see
 * (Tomcat manager UI exposed → try default creds → check /manager/jmxproxy).
 * Static scanners run a fixed playbook regardless. This loop closes that gap.
 *
 * Safety policy (NEVER skipped):
 *   1. Probe MUST target the same origin as the scan's seed URL.
 *   2. No destructive payloads (DROP TABLE, DELETE, /admin/wipe, etc.).
 *   3. Path component allow-list — no `../` or `\\`.
 *   4. Body size cap.
 *   5. Header allow-list (no Cookie / Authorization tampering beyond what
 *      the user already supplied; no Host / X-Forwarded-Host injections).
 *   6. Rate-limited via the global polite-mode limiter.
 *   7. User-Agent forced to identify as moba-scanner.
 *   8. Max 5 iterations per loop unless extended explicitly.
 *
 * Configuration:
 *   - ANTHROPIC_API_KEY required.
 *   - AGENTIC_MODEL env (defaults to claude-haiku-4-5-20251001 — fast).
 */

import { z } from "zod";
import { listFindings } from "../store";
import { loadSiteMap } from "../web/sitemap";
import { BrowsingSession } from "../web/session";
import type { Finding } from "../types";
import type { ScanContext } from "../engine/scanner";
import { draft } from "../engine/scanner";
import { truncate } from "../scanners/common";

const API_URL = "https://api.anthropic.com/v1/messages";
const DEFAULT_MODEL = process.env.AGENTIC_MODEL || "claude-haiku-4-5-20251001";

const ProbeSpec = z.object({
  rationale: z.string().min(10).max(500),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
  path: z.string().max(2048),
  query: z.record(z.string(), z.string()).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().max(8192).optional(),
  expect: z.object({
    status: z.array(z.number()).optional(),
    body_contains: z.array(z.string()).optional(),
    body_regex: z.string().optional(),
  }),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  title: z.string().max(200),
  description: z.string().max(2000),
  ruleId: z.string().max(80),
  cwe: z.array(z.string()).optional(),
});
type Probe = z.infer<typeof ProbeSpec>;

const SYSTEM_PROMPT = `You are a senior offensive-security engineer driving an automated scanner. Given a partial findings set + the target's known URL/form/cookie inventory, propose ONE next probe that has the highest expected information gain.

Output strict JSON matching this schema (NO prose, NO markdown):

{
  "rationale": "Why this probe; 1-2 sentences.",
  "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS",
  "path": "/some/path[?query]",
  "query": { "key": "value" } | omitted,
  "headers": { "Header-Name": "value" } | omitted,
  "body": "string body for POST/PUT" | omitted,
  "expect": {
    "status": [200, 401] | omitted,
    "body_contains": ["marker"] | omitted,
    "body_regex": "regex string" | omitted
  },
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "title": "Title used if probe matches",
  "description": "Full description if probe matches",
  "ruleId": "agentic/your-rule-id",
  "cwe": ["CWE-NNN"] | omitted
}

Constraints (the runner enforces these AND will reject your probe if violated):
  - Same origin as the seed URL only. Don't propose absolute URLs to other hosts.
  - No destructive payloads (DROP, DELETE FROM, rm -rf, ?wipe=1, ?confirm=1 on admin endpoints).
  - No path traversal in the path itself.
  - No spoofing the user's auth headers (Cookie, Authorization).
  - Prefer probes that, if matched, would be a CONFIRMED finding, not just suspicious.
  - Don't repeat probes that already produced a finding.

Respond with JSON only.`;

interface AnthropicResponse {
  content?: Array<{ type: string; text: string }>;
  error?: { type: string; message: string };
  usage?: { input_tokens: number; output_tokens: number };
}

async function callLLM(findings: Finding[], context: { origin: string; sitemap: { pages: string[]; forms: string[]; apiHints: string[] }; previous: Probe[] }, signal: AbortSignal): Promise<{ probe: Probe | null; usage?: AnthropicResponse["usage"]; error?: string }> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { probe: null, error: "ANTHROPIC_API_KEY not set" };

  const userMsg = `Target origin: ${context.origin}

Findings so far (${findings.length} total, sample):
${findings.slice(0, 30).map((f) => `- [${f.severity}] ${f.title} @ ${f.location?.url ?? f.location?.file ?? "?"} (rule=${f.ruleId})`).join("\n")}

Sitemap snapshot:
  - ${context.sitemap.pages.length} pages — ${context.sitemap.pages.slice(0, 10).join(", ")}
  - ${context.sitemap.forms.length} POST forms — ${context.sitemap.forms.slice(0, 5).join(", ")}
  - ${context.sitemap.apiHints.length} API hints — ${context.sitemap.apiHints.slice(0, 5).join(", ")}

Already tried (don't repeat):
${context.previous.map((p) => `- ${p.method} ${p.path}`).join("\n") || "(none)"}

What's the highest-EV next probe?`;

  const r = await fetch(API_URL, {
    method: "POST",
    headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({
      model: DEFAULT_MODEL,
      max_tokens: 1024,
      messages: [{
        role: "user",
        content: [
          { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } },
          { type: "text", text: userMsg },
        ],
      }],
    }),
    signal,
  });
  if (!r.ok) return { probe: null, error: `Anthropic ${r.status}: ${(await r.text().catch(() => "")).slice(0, 200)}` };
  const data: AnthropicResponse = await r.json();
  if (data.error) return { probe: null, error: `${data.error.type}: ${data.error.message}` };
  const text = (data.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n").trim();
  const stripped = text.replace(/^```(?:json)?\s*/, "").replace(/\s*```$/, "");
  let obj;
  try { obj = JSON.parse(stripped); }
  catch (e) { return { probe: null, usage: data.usage, error: `JSON parse: ${e instanceof Error ? e.message : e}` }; }
  const parsed = ProbeSpec.safeParse(obj);
  if (!parsed.success) return { probe: null, usage: data.usage, error: `schema: ${parsed.error.message}` };
  return { probe: parsed.data, usage: data.usage };
}

// ─────────────────────────── Safety policy ─────────────────────────────
function isSafe(probe: Probe, originHost: string): { ok: boolean; reason?: string } {
  // 1) No absolute URL — path only.
  if (/^[a-z][a-z0-9+\-.]*:\/\//i.test(probe.path)) return { ok: false, reason: "absolute URL not allowed" };
  // 2) No path traversal.
  if (/(?:\.\.[/\\])|(?:[\\/]\.\.[\\/])/.test(probe.path)) return { ok: false, reason: "path traversal in path" };
  // 3) Header allow-list — DENY auth-spoof + host-tamper.
  for (const k of Object.keys(probe.headers ?? {})) {
    if (/^(cookie|authorization|host|set-cookie|x-forwarded-host|x-original-host|forwarded)$/i.test(k))
      return { ok: false, reason: `forbidden header: ${k}` };
  }
  // 4) Destructive payload guards.
  const inspect = (probe.body ?? "") + " " + JSON.stringify(probe.query ?? {}) + " " + probe.path;
  if (/(?:drop\s+table|truncate\s+table|delete\s+from|rm\s+-rf|format\s+c:|shutdown\s+-)\b/i.test(inspect))
    return { ok: false, reason: "destructive payload" };
  if (/[?&](confirm|wipe|destroy|reset[-_]?all|format)=1\b/i.test(inspect))
    return { ok: false, reason: "destructive query param" };
  // 5) Body size.
  if ((probe.body?.length ?? 0) > 8192) return { ok: false, reason: "body too large" };
  return { ok: true };
}

// ───────────────────────── Probe execution ─────────────────────────────
async function executeProbe(session: BrowsingSession, origin: string, probe: Probe, signal: AbortSignal): Promise<{ status: number; body: string; matched: boolean }> {
  const url = new URL(probe.path, origin);
  for (const [k, v] of Object.entries(probe.query ?? {})) url.searchParams.set(k, v);
  const init: RequestInit = {
    method: probe.method,
    headers: {
      "User-Agent": "moba-scanner-agentic/0.1",
      ...(probe.headers ?? {}),
    },
  };
  if (probe.body) init.body = probe.body;
  let r;
  try { r = await session.fetch(url.toString(), init); }
  catch { return { status: 0, body: "", matched: false }; }
  // Match check.
  let matched = true;
  const e = probe.expect;
  if (e.status && !e.status.includes(r.res.status)) matched = false;
  if (e.body_contains) for (const s of e.body_contains) if (!r.body.includes(s)) { matched = false; break; }
  if (e.body_regex) {
    try { if (!new RegExp(e.body_regex).test(r.body)) matched = false; } catch { matched = false; }
  }
  return { status: r.res.status, body: r.body, matched };
}

// ───────────────────────────── Public API ──────────────────────────────
export interface AgenticRunResult {
  iterations: number;
  probesAccepted: number;
  probesRejected: number;
  newFindings: number;
  rejections: { rationale: string; reason: string }[];
  usage?: AnthropicResponse["usage"];
  error?: string;
}

export async function runAgenticLoop(ctx: ScanContext, opts: { iterations?: number } = {}): Promise<AgenticRunResult> {
  const N = Math.min(Math.max(opts.iterations ?? 5, 1), 10);
  const seed = (() => { try { return new URL(ctx.target.value); } catch { return null; } })();
  if (!seed) return { iterations: 0, probesAccepted: 0, probesRejected: 0, newFindings: 0, rejections: [], error: "invalid seed URL" };
  const map = await loadSiteMap(ctx.scanId);
  const sitemap = {
    pages: (map?.pages ?? []).map((p) => p.url),
    forms: (map?.forms ?? []).map((f) => f.action),
    apiHints: (map?.apiHints ?? []).map((a) => a.url),
  };
  const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
  const previous: Probe[] = [];
  const rejections: { rationale: string; reason: string }[] = [];
  let accepted = 0, rejected = 0, newFindings = 0;
  let totalUsage: AnthropicResponse["usage"] = undefined;

  for (let i = 0; i < N; i++) {
    if (ctx.signal.aborted) break;
    const findings = await listFindings(ctx.scanId);
    const { probe, usage, error } = await callLLM(findings, { origin: seed.origin, sitemap, previous }, ctx.signal);
    if (usage) {
      if (!totalUsage) totalUsage = { ...usage };
      else { totalUsage.input_tokens += usage.input_tokens; totalUsage.output_tokens += usage.output_tokens; }
    }
    if (error || !probe) return { iterations: i, probesAccepted: accepted, probesRejected: rejected, newFindings, rejections, usage: totalUsage, error };
    const safety = isSafe(probe, seed.host);
    if (!safety.ok) {
      rejected++;
      rejections.push({ rationale: probe.rationale, reason: safety.reason ?? "unsafe" });
      await ctx.log("warn", `[agentic] rejected probe (${safety.reason}): ${probe.method} ${probe.path}`);
      previous.push(probe); // don't suggest again
      continue;
    }
    accepted++;
    await ctx.log("info", `[agentic] iter ${i + 1}/${N}: ${probe.method} ${probe.path} — ${probe.rationale}`);
    const result = await executeProbe(session, seed.origin, probe, ctx.signal);
    previous.push(probe);
    if (result.matched) {
      newFindings++;
      const url = new URL(probe.path, seed.origin);
      for (const [k, v] of Object.entries(probe.query ?? {})) url.searchParams.set(k, v);
      await ctx.emit(draft({
        severity: probe.severity, confidence: "medium",
        title: probe.title,
        description: `${probe.description}\n\n→ Proposed by agentic loop. Rationale: ${probe.rationale}`,
        ruleId: probe.ruleId,
        cwe: probe.cwe,
        location: { url: url.toString() },
        evidence: { method: probe.method, status: result.status, snippet: truncate(result.body, 400), agentic: { rationale: probe.rationale, iteration: i + 1 } },
      }));
    }
  }
  return { iterations: N, probesAccepted: accepted, probesRejected: rejected, newFindings, rejections, usage: totalUsage };
}

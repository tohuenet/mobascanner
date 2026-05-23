/**
 * LLM-driven triage for scan findings.
 *
 * What this does for each finding:
 *   1. Decides whether the finding looks like a real vulnerability (vs.
 *      false-positive / needs-confirmation), with a short reason.
 *   2. Adjusts severity if the LLM has higher-fidelity context than the
 *      static rule (e.g. an XSS in a public marketing site is lower
 *      blast-radius than the same XSS on the auth subdomain).
 *   3. Produces an attacker-narrative + a concrete code-level remediation,
 *      which we attach to `finding.evidence.triage` so the UI can render it.
 *
 * Configuration:
 *   - ANTHROPIC_API_KEY env var is required.
 *   - We use claude-haiku-4-5 by default (fast + cheap, fine for triage).
 *     Override via TRIAGE_MODEL env var.
 *   - Prompt caching is enabled on the system + rules block so cost stays
 *     low when triaging many findings in one scan.
 *
 * No external SDK dependency — this calls the Messages API via fetch.
 */

import type { Finding, Severity } from "../types";

const API_URL = "https://api.anthropic.com/v1/messages";
const DEFAULT_MODEL = process.env.TRIAGE_MODEL || "claude-haiku-4-5-20251001";

const SYSTEM_PROMPT = `You are a senior application-security analyst triaging findings from an automated scanner. For each finding the user supplies you decide:

1. is_real (true | false | needs_confirmation)
   - "false" only when the finding is clearly a false positive (e.g. a regex hit inside test fixtures, a CVE in a dev-only tool, a missing header on a documented preview environment)
   - "needs_confirmation" if the rule is correct but you cannot tell from the evidence whether it's exploitable
   - otherwise "true"

2. severity (critical | high | medium | low | info)
   - Use the original severity as a starting point.
   - Reduce when the asset / context lowers blast radius.
   - Raise when chained context (e.g. cookie missing HttpOnly + reflected XSS) makes exploitation more likely.

3. attacker_narrative (1–3 sentences)
   - A specific, technical exploitation story. No filler.

4. remediation (1–4 sentences, can include a tiny code snippet)
   - Concrete, actionable, language-aware.

5. confidence (0.0–1.0)
   - Your confidence in the triage decision, NOT the original scanner confidence.

Reply with strict JSON only — an array of objects in the same order as inputs, with keys: id, is_real, severity, attacker_narrative, remediation, confidence. No prose, no markdown.`;

export interface TriageDecision {
  id: string;
  is_real: "true" | "false" | "needs_confirmation";
  severity: Severity;
  attacker_narrative: string;
  remediation: string;
  confidence: number;
}

interface AnthropicMessage {
  role: "user" | "assistant";
  content: Array<{ type: "text"; text: string; cache_control?: { type: "ephemeral" } }>;
}

interface AnthropicResponse {
  content?: Array<{ type: string; text: string }>;
  usage?: { input_tokens: number; cache_read_input_tokens?: number; cache_creation_input_tokens?: number; output_tokens: number };
  error?: { type: string; message: string };
}

function summarize(f: Finding): Record<string, unknown> {
  // Trim noisy fields so we don't blow the context window.
  const evidence = f.evidence
    ? Object.fromEntries(Object.entries(f.evidence).map(([k, v]) => {
        const s = typeof v === "string" ? v : JSON.stringify(v);
        return [k, s.length > 600 ? s.slice(0, 600) + "…" : v];
      }))
    : undefined;
  return {
    id: f.id,
    scanner: f.scannerId,
    title: f.title,
    description: f.description?.slice(0, 800),
    severity: f.severity,
    confidence: f.confidence,
    rule: f.ruleId,
    cwe: f.cwe,
    cve: f.cve,
    owasp: f.owasp,
    location: f.location,
    evidence,
  };
}

export async function triageFindings(
  findings: Finding[],
  opts: { model?: string; signal?: AbortSignal } = {},
): Promise<{ decisions: TriageDecision[]; usage: AnthropicResponse["usage"]; error?: string }> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { decisions: [], usage: undefined, error: "ANTHROPIC_API_KEY not set" };
  if (!findings.length) return { decisions: [], usage: undefined };

  // Batch up to 25 findings per request to balance latency / cost.
  const BATCH = 25;
  const all: TriageDecision[] = [];
  let totalUsage: AnthropicResponse["usage"] = undefined;

  for (let i = 0; i < findings.length; i += BATCH) {
    const batch = findings.slice(i, i + BATCH);
    const userText = `Triage these ${batch.length} findings. Respond with JSON only.\n\n` +
      JSON.stringify(batch.map(summarize), null, 2);

    const messages: AnthropicMessage[] = [{
      role: "user",
      content: [
        { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } },
        { type: "text", text: userText },
      ],
    }];

    const res = await fetch(API_URL, {
      method: "POST",
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: opts.model ?? DEFAULT_MODEL,
        max_tokens: 4096,
        messages,
      }),
      signal: opts.signal,
    });
    if (!res.ok) {
      const err = await res.text().catch(() => "");
      return { decisions: all, usage: totalUsage, error: `Anthropic API ${res.status}: ${err.slice(0, 200)}` };
    }
    const data: AnthropicResponse = await res.json();
    if (data.error) return { decisions: all, usage: totalUsage, error: `${data.error.type}: ${data.error.message}` };

    if (data.usage) {
      if (!totalUsage) totalUsage = { ...data.usage };
      else {
        totalUsage.input_tokens += data.usage.input_tokens;
        totalUsage.output_tokens += data.usage.output_tokens;
        totalUsage.cache_read_input_tokens = (totalUsage.cache_read_input_tokens ?? 0) + (data.usage.cache_read_input_tokens ?? 0);
        totalUsage.cache_creation_input_tokens = (totalUsage.cache_creation_input_tokens ?? 0) + (data.usage.cache_creation_input_tokens ?? 0);
      }
    }

    const text = (data.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n").trim();
    // Strip markdown code fences if model wraps JSON.
    const stripped = text.replace(/^```(?:json)?\s*/, "").replace(/\s*```$/, "");
    let parsed: TriageDecision[];
    try { parsed = JSON.parse(stripped); }
    catch (e) {
      return { decisions: all, usage: totalUsage, error: `JSON parse failed: ${e instanceof Error ? e.message : e}` };
    }
    all.push(...parsed);
  }

  return { decisions: all, usage: totalUsage };
}

/** Apply triage decisions to a finding set. Returns updated findings. */
export function mergeTriage(findings: Finding[], decisions: TriageDecision[]): Finding[] {
  const byId = new Map(decisions.map((d) => [d.id, d]));
  return findings.map((f) => {
    const d = byId.get(f.id);
    if (!d) return f;
    return {
      ...f,
      severity: d.severity ?? f.severity,
      triage: {
        state: d.is_real === "false" ? "false-positive" : "open",
        note: `${d.attacker_narrative}\n\nRemediation: ${d.remediation}`,
        by: "llm",
        at: Date.now(),
      },
      evidence: {
        ...(f.evidence ?? {}),
        llm_triage: {
          is_real: d.is_real,
          confidence: d.confidence,
          attacker_narrative: d.attacker_narrative,
          remediation: d.remediation,
        },
      },
    };
  });
}

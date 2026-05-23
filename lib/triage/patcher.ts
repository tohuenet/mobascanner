/**
 * LLM patch generation — for source-side findings, ask Claude for a
 * unified-diff fix. Returns proposals (reviewable) — never writes to the
 * filesystem.
 *
 * Flow:
 *   1. Caller posts a finding id.
 *   2. We read the surrounding source file (10 lines context above + below).
 *   3. Ask Claude for a fix that:
 *        - keeps the same public API
 *        - preserves comments / formatting
 *        - explains the change in 1-2 sentences
 *   4. Return as `{ patch: <unified diff>, explanation: <text>, confidence }`.
 *
 * For web findings, we generate a remediation snippet (Nginx config / CSP / etc.)
 * instead of a code patch.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import type { Finding } from "../types";

const API_URL = "https://api.anthropic.com/v1/messages";
const MODEL = process.env.PATCH_MODEL || process.env.TRIAGE_MODEL || "claude-haiku-4-5-20251001";

const SYSTEM_PROMPT = `You are a senior security engineer producing minimal, reviewable code patches.

For source-side findings, output a UNIFIED DIFF (\`--- a/file\` / \`+++ b/file\` / \`@@ … @@\`) that:
  - Fixes the root cause (don't suppress, don't comment-out, don't \`// eslint-disable\`).
  - Preserves the surrounding code's style (indent, quotes, semicolons).
  - Adds the smallest necessary import / declaration.
  - Doesn't touch unrelated lines.

For web findings (no file path), output a SHORT remediation snippet — Nginx config, CSP header, framework-level setting — in a fenced code block with the right language hint.

Reply with strict JSON:
{
  "kind": "diff" | "snippet",
  "patch": "<unified diff or snippet>",
  "explanation": "1-2 sentences explaining what changed and why.",
  "confidence": 0.0-1.0,
  "warnings": ["..."]
}`;

interface ClaudeResp {
  content?: Array<{ type: string; text: string }>;
  usage?: { input_tokens: number; output_tokens: number };
  error?: { type: string; message: string };
}

export interface PatchResult {
  kind: "diff" | "snippet" | null;
  patch: string;
  explanation: string;
  confidence: number;
  warnings: string[];
  usage?: ClaudeResp["usage"];
  error?: string;
}

async function readContext(filePath: string, line?: number): Promise<{ snippet: string; absPath: string } | null> {
  const root = path.join(process.cwd(), "data", "repos");
  // Try to find the file inside a known repo dir.
  let absPath: string | null = null;
  try {
    for (const e of await fs.readdir(root)) {
      const candidate = path.join(root, e, filePath);
      try { await fs.access(candidate); absPath = candidate; break; } catch { /* keep searching */ }
    }
  } catch { /* no repos dir */ }
  if (!absPath) {
    // Maybe the path is absolute / relative to cwd.
    try { await fs.access(filePath); absPath = filePath; } catch { return null; }
  }
  let content;
  try { content = await fs.readFile(absPath, "utf8"); } catch { return null; }
  const lines = content.split("\n");
  const ln = (line ?? Math.floor(lines.length / 2)) - 1;
  const start = Math.max(0, ln - 10);
  const end = Math.min(lines.length, ln + 11);
  const snippet = lines.slice(start, end).map((l, i) => `${start + i + 1}\t${l}`).join("\n");
  return { snippet, absPath };
}

export async function generatePatch(finding: Finding): Promise<PatchResult> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  const empty: PatchResult = { kind: null, patch: "", explanation: "", confidence: 0, warnings: [] };
  if (!apiKey) return { ...empty, error: "ANTHROPIC_API_KEY not set" };

  const file = finding.location.file;
  let context: { snippet: string; absPath: string } | null = null;
  if (file) context = await readContext(file, finding.location.line);

  const userPrompt = `Finding to fix:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Rule: ${finding.ruleId ?? "?"}
- CWE: ${(finding.cwe ?? []).join(", ") || "n/a"}
- OWASP: ${(finding.owasp ?? []).join(", ") || "n/a"}
- Location: ${file ?? finding.location.url ?? "unknown"}${finding.location.line ? `:${finding.location.line}` : ""}

Description:
${finding.description.slice(0, 2000)}

Existing remediation hint (rewrite if better):
${finding.remediation ?? "(none)"}
${context ? `\nSource context (line numbers prefixed):\n\`\`\`\n${context.snippet}\n\`\`\`` : "\n(no source file available — produce a remediation snippet instead of a diff)"}

Produce JSON only.`;

  let res;
  try {
    res = await fetch(API_URL, {
      method: "POST",
      headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 2048,
        messages: [{
          role: "user",
          content: [
            { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } },
            { type: "text", text: userPrompt },
          ],
        }],
      }),
    });
  } catch (e) { return { ...empty, error: e instanceof Error ? e.message : String(e) }; }
  if (!res.ok) return { ...empty, error: `Anthropic ${res.status}: ${(await res.text().catch(() => "")).slice(0, 200)}` };
  const data: ClaudeResp = await res.json();
  if (data.error) return { ...empty, error: `${data.error.type}: ${data.error.message}` };

  const text = (data.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n").trim();
  const stripped = text.replace(/^```(?:json)?\s*/, "").replace(/\s*```$/, "");
  try {
    const j = JSON.parse(stripped);
    return {
      kind: j.kind ?? null,
      patch: j.patch ?? "",
      explanation: j.explanation ?? "",
      confidence: Number(j.confidence ?? 0),
      warnings: Array.isArray(j.warnings) ? j.warnings : [],
      usage: data.usage,
    };
  } catch (e) {
    return { ...empty, usage: data.usage, error: `JSON parse: ${e instanceof Error ? e.message : e}` };
  }
}

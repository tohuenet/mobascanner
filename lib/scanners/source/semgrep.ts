/**
 * Semgrep adapter — runs `semgrep scan --json` over the resolved source tree.
 *
 * Default ruleset: `auto` (Semgrep picks rule packs based on detected
 * languages). Users can override via `options.config` (e.g. "p/owasp-top-ten").
 *
 * Schema reference: https://semgrep.dev/docs/cli-reference/
 */

import path from "node:path";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, truncate } from "../common";
import { resolveSourceTarget } from "./git-import";

interface SemgrepResult {
  results?: Array<{
    check_id: string;
    path: string;
    start: { line: number; col: number };
    end:   { line: number; col: number };
    extra: {
      message: string;
      severity?: "INFO" | "WARNING" | "ERROR";
      lines?: string;
      metadata?: {
        cwe?: string[];
        owasp?: string[];
        references?: string[];
        category?: string;
        technology?: string[];
        impact?: string;
        likelihood?: string;
      };
      fix?: string;
    };
  }>;
  errors?: Array<{ message: string }>;
}

const SEV_MAP: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "low",
};

export const semgrepScanner: Scanner = {
  id: "source.semgrep",
  name: "Semgrep",
  kind: "source",
  description: "Static analysis using Semgrep rules — runs the curated `auto` ruleset by default; configure `options.config` for OWASP / language-specific packs.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("semgrep", "--version");
    return {
      id: "source.semgrep",
      name: "Semgrep",
      kind: "source",
      backend: "cli",
      cliCommand: "semgrep",
      cliVersionArg: "--version",
      status: v ? "available" : "missing",
      detectedVersion: v ?? undefined,
      installHint: "`pip install semgrep` or `brew install semgrep`",
      upstream: "https://github.com/semgrep/semgrep",
      license: "LGPL-2.1",
      description: "Multi-language static analysis with thousands of community rules.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("semgrep", "--version");
    if (!v) { await ctx.log("warn", "semgrep not found — skipping"); return; }

    const config = (ctx.options.config as string) ?? "auto";
    const args = ["scan", "--json", "--quiet", "--config", config, "--metrics=off", root];
    await ctx.log("info", `semgrep ${v}, config=${config}`);

    const r = await runCli("semgrep", args, {
      signal: ctx.signal,
      timeoutMs: 60 * 60 * 1000,
      maxBufferBytes: 256 * 1024 * 1024,
      onStderr: async (line) => { if (line.trim()) await ctx.log("info", line.trim()); },
    });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    if (!r.stdout.trim()) { await ctx.log("warn", "semgrep returned no JSON"); return; }

    let parsed: SemgrepResult;
    try { parsed = JSON.parse(r.stdout); }
    catch (e) { await ctx.log("error", `parse semgrep JSON failed: ${e instanceof Error ? e.message : e}`); return; }

    const results = parsed.results ?? [];
    await ctx.progress(0.5, `${results.length} results`);

    for (const res of results) {
      const sev = SEV_MAP[res.extra.severity ?? "INFO"] ?? "low";
      await ctx.emit(draft({
        severity: sev,
        confidence: "medium",
        title: res.extra.message?.split("\n")[0]?.slice(0, 200) ?? res.check_id,
        description: res.extra.message ?? "",
        ruleId: res.check_id,
        cwe: res.extra.metadata?.cwe,
        owasp: res.extra.metadata?.owasp,
        references: res.extra.metadata?.references,
        location: {
          file: path.relative(root, res.path).replace(/\\/g, "/"),
          line: res.start.line,
          column: res.start.col,
          endLine: res.end.line,
          snippet: truncate(res.extra.lines ?? "", 400),
        },
        evidence: {
          check_id: res.check_id,
          metadata: res.extra.metadata,
          fix: res.extra.fix,
        },
        remediation: res.extra.fix ? `Suggested fix: ${truncate(res.extra.fix, 200)}` : undefined,
      }));
    }

    await ctx.progress(1, "semgrep done");
  },
};

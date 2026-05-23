/**
 * gitleaks adapter — secret scanning over git history.
 *
 * `gitleaks detect --no-banner --report-format json --report-path -` writes
 * the JSON report to a file path; we use a tempfile and read it back so we
 * don't have to rely on stdout JSON behavior across versions.
 */

import path from "node:path";
import os from "node:os";
import { promises as fs } from "node:fs";
import { randomUUID } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, truncate } from "../common";
import { resolveSourceTarget } from "./git-import";

interface GitleaksFinding {
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  SymlinkFile?: string;
  Commit?: string;
  Entropy?: number;
  Author?: string;
  Email?: string;
  Date?: string;
  Message?: string;
  Tags?: string[];
  RuleID?: string;
  Fingerprint?: string;
}

export const gitleaksScanner: Scanner = {
  id: "source.gitleaks",
  name: "Gitleaks",
  kind: "source",
  description: "Detects committed secrets across the git history using the gitleaks rule set. Falls back gracefully if the binary isn't installed.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("gitleaks", "version");
    return {
      id: "source.gitleaks",
      name: "Gitleaks",
      kind: "source",
      backend: "cli",
      cliCommand: "gitleaks",
      cliVersionArg: "version",
      status: v ? "available" : "missing",
      detectedVersion: v ?? undefined,
      installHint: "`brew install gitleaks` / `go install github.com/gitleaks/gitleaks/v8@latest` / GitHub releases",
      upstream: "https://github.com/gitleaks/gitleaks",
      license: "MIT",
      description: "Secret detection in git repositories.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("gitleaks", "version");
    if (!v) { await ctx.log("warn", "gitleaks not found — skipping"); return; }

    const reportPath = path.join(os.tmpdir(), `gitleaks-${randomUUID()}.json`);
    const args = ["detect", "--source", root, "--no-banner", "--redact", "--report-format", "json", "--report-path", reportPath];

    await ctx.log("info", `gitleaks ${v}`);
    const r = await runCli("gitleaks", args, { signal: ctx.signal, timeoutMs: 30 * 60 * 1000 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }

    let raw: string;
    try { raw = await fs.readFile(reportPath, "utf8"); }
    catch { await ctx.log("warn", "no gitleaks report produced"); return; }
    finally { fs.rm(reportPath, { force: true }).catch(() => {}); }

    let findings: GitleaksFinding[];
    try { findings = JSON.parse(raw) as GitleaksFinding[]; }
    catch (e) { await ctx.log("error", `gitleaks JSON parse: ${e instanceof Error ? e.message : e}`); return; }

    for (const f of findings) {
      await ctx.emit(draft({
        severity: "high",
        confidence: "high",
        title: `${f.RuleID ?? f.Description ?? "Secret"} found in ${f.File ?? "?"}`,
        description: f.Description ?? "Gitleaks rule matched",
        ruleId: f.RuleID ? `gitleaks/${f.RuleID}` : "gitleaks",
        cwe: ["CWE-798"],
        owasp: ["A07:2021"],
        location: {
          file: f.File ? path.relative(root, f.File).replace(/\\/g, "/") : undefined,
          line: f.StartLine,
          column: f.StartColumn,
          endLine: f.EndLine,
          snippet: truncate(f.Match ?? "", 200),
        },
        evidence: {
          fingerprint: f.Fingerprint,
          commit: f.Commit,
          author: f.Author,
          date: f.Date,
          tags: f.Tags,
          entropy: f.Entropy,
        },
        remediation: "Rotate the secret immediately, purge it from git history, and store via env vars or a secrets manager.",
        references: ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
      }));
    }

    await ctx.progress(1, `${findings.length} gitleaks findings`);
  },
};

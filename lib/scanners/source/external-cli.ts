/**
 * Source-side external CLI adapters:
 *
 *   - osv-scanner   → Google's OSV.dev-backed dep CVE scanner
 *   - bandit        → Python SAST
 *   - brakeman      → Ruby on Rails SAST
 *   - eslint        → JS/TS via the security plugin (eslint-plugin-security)
 *   - checkov       → Terraform / Kubernetes / CloudFormation IaC
 */

import path from "node:path";
import os from "node:os";
import { promises as fs } from "node:fs";
import { randomUUID } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, truncate } from "../common";
import { resolveSourceTarget } from "./git-import";

const SEV: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low",
  Critical: "critical", High: "high", Medium: "medium", Low: "low",
  ERROR: "high", WARN: "medium", INFO: "low",
};

// ─────────────────────────── osv-scanner ────────────────────────
export const osvScanner: Scanner = {
  id: "source.osv-scanner",
  name: "osv-scanner",
  kind: "source",
  description: "Google's OSV.dev-backed dependency CVE scanner. Reads lockfiles for npm / pip / go / cargo / maven / etc.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("osv-scanner", "--version");
    return {
      id: "source.osv-scanner", name: "osv-scanner", kind: "source", backend: "cli",
      cliCommand: "osv-scanner", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`brew install osv-scanner` / `go install github.com/google/osv-scanner/cmd/osv-scanner@latest`",
      upstream: "https://github.com/google/osv-scanner",
      license: "Apache-2.0",
      description: "OSV.dev-backed dependency CVE scanner.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("osv-scanner", "--version");
    if (!v) { await ctx.log("warn", "osv-scanner not found"); return; }
    const r = await runCli("osv-scanner", ["--format", "json", "scan", "source", "-r", root], {
      signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 256 * 1024 * 1024,
    });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    if (!r.stdout.trim()) return;
    let parsed: { results?: Array<{ source?: { path?: string }; packages?: Array<{ package: { name: string; version: string }; vulnerabilities?: Array<{ id: string; summary?: string; details?: string; severity?: Array<{ score?: string }>; aliases?: string[]; references?: Array<{ url?: string }> }> }> }> };
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    let n = 0;
    for (const res of parsed.results ?? []) {
      const target = res.source?.path ? path.relative(root, res.source.path).replace(/\\/g, "/") : "";
      for (const p of res.packages ?? []) {
        for (const vu of p.vulnerabilities ?? []) {
          n += 1;
          const cve = (vu.aliases ?? []).filter((a) => /^CVE-/i.test(a));
          const score = (vu.severity ?? []).find((s) => /CVSS_V3:.*?\/(\d+(\.\d+)?)/.exec(s.score ?? ""));
          await ctx.emit(draft({
            severity: cve.length ? "high" : "medium",
            confidence: "high",
            title: `${p.package.name}@${p.package.version} — ${vu.id}`,
            description: vu.summary ?? vu.details ?? "",
            ruleId: vu.id,
            cve,
            location: { file: target },
            evidence: { pkg: p.package.name, version: p.package.version, score: score?.score },
            references: (vu.references ?? []).map((r) => r.url).filter((u): u is string => Boolean(u)),
          }));
        }
      }
    }
    await ctx.progress(1, `${n} osv findings`);
  },
};

// ─────────────────────────── bandit (Python) ────────────────────
export const banditScanner: Scanner = {
  id: "source.bandit",
  name: "bandit",
  kind: "source",
  description: "Python AST static analysis from the OpenStack security team — flags shell injection, weak crypto, hardcoded secrets, etc.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("bandit", "--version");
    return {
      id: "source.bandit", name: "bandit", kind: "source", backend: "cli",
      cliCommand: "bandit", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`pip install bandit`",
      upstream: "https://github.com/PyCQA/bandit",
      license: "Apache-2.0",
      description: "Python SAST.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("bandit", "--version");
    if (!v) { await ctx.log("warn", "bandit not found"); return; }
    const r = await runCli("bandit", ["-r", root, "-f", "json", "-q"], {
      signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 64 * 1024 * 1024,
    });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    if (!r.stdout.trim()) return;
    let parsed: { results?: Array<{ filename: string; issue_severity: string; issue_confidence: string; issue_text: string; test_id: string; test_name: string; line_number: number; code: string; cwe?: { id?: string; link?: string } }> };
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    for (const res of parsed.results ?? []) {
      await ctx.emit(draft({
        severity: SEV[res.issue_severity] ?? "low",
        confidence: res.issue_confidence === "HIGH" ? "high" : res.issue_confidence === "MEDIUM" ? "medium" : "low",
        title: `bandit ${res.test_id}: ${res.test_name}`,
        description: res.issue_text,
        ruleId: `bandit/${res.test_id}`,
        cwe: res.cwe?.id ? [`CWE-${res.cwe.id}`] : undefined,
        location: { file: path.relative(root, res.filename).replace(/\\/g, "/"), line: res.line_number, snippet: truncate(res.code, 300) },
      }));
    }
    await ctx.progress(1, `${(parsed.results ?? []).length} bandit findings`);
  },
};

// ─────────────────────────── brakeman (Rails) ───────────────────
export const brakemanScanner: Scanner = {
  id: "source.brakeman",
  name: "brakeman",
  kind: "source",
  description: "Static analysis for Ruby on Rails — XSS, SQLi, mass assignment, unsafe deserialization, and more.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("brakeman", "--version");
    return {
      id: "source.brakeman", name: "brakeman", kind: "source", backend: "cli",
      cliCommand: "brakeman", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`gem install brakeman`",
      upstream: "https://github.com/presidentbeef/brakeman",
      license: "MIT",
      description: "Ruby on Rails SAST.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("brakeman", "--version");
    if (!v) { await ctx.log("warn", "brakeman not found"); return; }
    const r = await runCli("brakeman", ["-q", "-f", "json", root], {
      signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 64 * 1024 * 1024,
    });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    if (!r.stdout.trim()) return;
    let parsed: { warnings?: Array<{ warning_type: string; warning_code: number; message: string; file: string; line: number; confidence: string; link: string; code?: string; cwe_id?: string[] }> };
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    for (const w of parsed.warnings ?? []) {
      await ctx.emit(draft({
        severity: w.confidence === "High" ? "high" : w.confidence === "Medium" ? "medium" : "low",
        confidence: w.confidence === "High" ? "high" : w.confidence === "Medium" ? "medium" : "low",
        title: `brakeman: ${w.warning_type}`,
        description: w.message,
        ruleId: `brakeman/${w.warning_code}`,
        cwe: w.cwe_id?.map((id) => `CWE-${id}`),
        location: { file: w.file, line: w.line, snippet: truncate(w.code ?? "", 200) },
        references: w.link ? [w.link] : undefined,
      }));
    }
    await ctx.progress(1, `${(parsed.warnings ?? []).length} brakeman findings`);
  },
};

// ─────────────────────────── eslint security ────────────────────
export const eslintSecurityScanner: Scanner = {
  id: "source.eslint-security",
  name: "ESLint (security)",
  kind: "source",
  description: "Runs ESLint against the source tree using eslint-plugin-security rules. Requires the project's own eslint config or a fallback config provided via options.config.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("eslint", "--version");
    return {
      id: "source.eslint-security", name: "ESLint (security)", kind: "source", backend: "cli",
      cliCommand: "eslint", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "Install eslint + eslint-plugin-security in the target project",
      upstream: "https://github.com/eslint-community/eslint-plugin-security",
      license: "Apache-2.0",
      description: "JS/TS lint with eslint-plugin-security rules (XSS, eval, regex DoS, child_process abuse).",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("eslint", "--version");
    if (!v) { await ctx.log("warn", "eslint not found"); return; }
    const args = ["--format", "json", "."];
    const r = await runCli("eslint", args, { cwd: root, signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 128 * 1024 * 1024 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    if (!r.stdout.trim()) return;
    let parsed: Array<{ filePath: string; messages?: Array<{ ruleId: string | null; severity: number; message: string; line: number; column: number; nodeType?: string; source?: string }> }>;
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    let n = 0;
    for (const file of parsed) {
      for (const msg of file.messages ?? []) {
        if (!msg.ruleId || !msg.ruleId.includes("security")) continue;
        n += 1;
        await ctx.emit(draft({
          severity: msg.severity === 2 ? "medium" : "low",
          confidence: "medium",
          title: `${msg.ruleId}: ${msg.message.slice(0, 120)}`,
          description: msg.message,
          ruleId: msg.ruleId,
          location: { file: path.relative(root, file.filePath).replace(/\\/g, "/"), line: msg.line, column: msg.column, snippet: truncate(msg.source ?? "", 200) },
        }));
      }
    }
    await ctx.progress(1, `${n} eslint security findings`);
  },
};

// ─────────────────────────── checkov (IaC) ──────────────────────
export const checkovScanner: Scanner = {
  id: "source.checkov",
  name: "checkov",
  kind: "source",
  description: "Bridgecrew/Prisma checkov — Terraform / CloudFormation / Kubernetes / Docker IaC misconfigurations.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("checkov", "--version");
    return {
      id: "source.checkov", name: "checkov", kind: "source", backend: "cli",
      cliCommand: "checkov", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`pip install checkov`",
      upstream: "https://github.com/bridgecrewio/checkov",
      license: "Apache-2.0",
      description: "IaC security scanner.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("checkov", "--version");
    if (!v) { await ctx.log("warn", "checkov not found"); return; }
    const out = path.join(os.tmpdir(), `checkov-${randomUUID()}.json`);
    const r = await runCli("checkov", ["-d", root, "-o", "json", "--quiet", "--soft-fail"], {
      signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 256 * 1024 * 1024,
    });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    if (!r.stdout.trim()) return;
    let parsed: { results?: { failed_checks?: Array<{ check_id: string; check_name: string; file_path: string; file_line_range?: number[]; severity?: string; guideline?: string }> } } | Array<{ results?: { failed_checks?: Array<{ check_id: string; check_name: string; file_path: string; file_line_range?: number[]; severity?: string; guideline?: string }> } }>;
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    finally { fs.rm(out, { force: true }).catch(() => {}); }
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    let n = 0;
    for (const block of arr) {
      for (const f of block.results?.failed_checks ?? []) {
        n += 1;
        await ctx.emit(draft({
          severity: SEV[(f.severity ?? "MEDIUM").toUpperCase()] ?? "medium",
          confidence: "high",
          title: `checkov ${f.check_id}: ${f.check_name}`,
          description: f.check_name,
          ruleId: f.check_id,
          location: { file: f.file_path?.replace(/^\//, ""), line: f.file_line_range?.[0] },
          references: f.guideline ? [f.guideline] : undefined,
        }));
      }
    }
    await ctx.progress(1, `${n} checkov findings`);
  },
};

/**
 * Trivy adapter — runs `trivy fs --format json` to surface vulnerabilities,
 * misconfigurations, license issues, and secrets in the source tree in a
 * single pass.
 *
 * Schema reference: https://aquasecurity.github.io/trivy/latest/docs/configuration/reporting/
 */

import path from "node:path";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, truncate } from "../common";
import { resolveSourceTarget } from "./git-import";

interface TrivyResult {
  Results?: Array<{
    Target: string;
    Class?: string;
    Type?: string;
    Vulnerabilities?: Array<{
      VulnerabilityID: string;
      PkgName: string;
      InstalledVersion: string;
      FixedVersion?: string;
      Severity: string;
      Title?: string;
      Description?: string;
      References?: string[];
      CweIDs?: string[];
      CVSS?: Record<string, { V3Score?: number }>;
      PrimaryURL?: string;
    }>;
    Misconfigurations?: Array<{
      ID: string;
      AVDID?: string;
      Title: string;
      Description: string;
      Severity: string;
      Resolution?: string;
      References?: string[];
      CauseMetadata?: { StartLine?: number; EndLine?: number };
    }>;
    Secrets?: Array<{
      RuleID: string;
      Category: string;
      Severity: string;
      Title: string;
      Match: string;
      StartLine?: number;
      EndLine?: number;
    }>;
  }>;
}

const SEV_MAP: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

export const trivyScanner: Scanner = {
  id: "source.trivy",
  name: "Trivy",
  kind: "source",
  description: "Aqua Security trivy: dependency CVEs, IaC misconfigurations, secrets, and license issues — all in one pass.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("trivy", "--version");
    return {
      id: "source.trivy",
      name: "Trivy",
      kind: "source",
      backend: "cli",
      cliCommand: "trivy",
      cliVersionArg: "--version",
      status: v ? "available" : "missing",
      detectedVersion: v ?? undefined,
      installHint: "`brew install trivy` / `apt install trivy` / GitHub releases",
      upstream: "https://github.com/aquasecurity/trivy",
      license: "Apache-2.0",
      description: "All-in-one CVE / IaC / secret scanner.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("trivy", "--version");
    if (!v) { await ctx.log("warn", "trivy not found — skipping"); return; }

    const args = [
      "fs",
      "--quiet",
      "--no-progress",
      "--format", "json",
      "--scanners", "vuln,misconfig,secret",
      "--exit-code", "0",
      root,
    ];
    await ctx.log("info", `trivy ${v}`);

    const r = await runCli("trivy", args, {
      signal: ctx.signal,
      timeoutMs: 60 * 60 * 1000,
      maxBufferBytes: 256 * 1024 * 1024,
    });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    if (!r.stdout.trim()) { await ctx.log("warn", "trivy produced no output"); return; }

    let parsed: TrivyResult;
    try { parsed = JSON.parse(r.stdout) as TrivyResult; }
    catch (e) { await ctx.log("error", `parse trivy JSON: ${e instanceof Error ? e.message : e}`); return; }

    let count = 0;
    for (const result of parsed.Results ?? []) {
      const targetFile = path.relative(root, result.Target).replace(/\\/g, "/");
      for (const vuln of result.Vulnerabilities ?? []) {
        count += 1;
        const v3 = vuln.CVSS?.["nvd"]?.V3Score ?? vuln.CVSS?.["redhat"]?.V3Score;
        await ctx.emit(draft({
          severity: SEV_MAP[vuln.Severity?.toUpperCase()] ?? "info",
          confidence: "high",
          title: `${vuln.PkgName}@${vuln.InstalledVersion} — ${vuln.VulnerabilityID}`,
          description: vuln.Title ?? vuln.Description ?? "",
          ruleId: vuln.VulnerabilityID,
          cve: [vuln.VulnerabilityID].filter((x) => /^CVE-/i.test(x)),
          cwe: vuln.CweIDs,
          cvss: v3,
          location: { file: targetFile },
          evidence: { pkg: vuln.PkgName, installed: vuln.InstalledVersion, fixed: vuln.FixedVersion },
          remediation: vuln.FixedVersion ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion}.` : "Apply upstream patch when available.",
          references: [vuln.PrimaryURL, ...(vuln.References ?? [])].filter((x): x is string => Boolean(x)),
        }));
      }
      for (const m of result.Misconfigurations ?? []) {
        count += 1;
        await ctx.emit(draft({
          severity: SEV_MAP[m.Severity?.toUpperCase()] ?? "info",
          confidence: "high",
          title: `${m.ID} — ${m.Title}`,
          description: m.Description,
          ruleId: m.AVDID ?? m.ID,
          location: {
            file: targetFile,
            line: m.CauseMetadata?.StartLine,
            endLine: m.CauseMetadata?.EndLine,
          },
          remediation: m.Resolution,
          references: m.References,
        }));
      }
      for (const s of result.Secrets ?? []) {
        count += 1;
        await ctx.emit(draft({
          severity: SEV_MAP[s.Severity?.toUpperCase()] ?? "high",
          confidence: "high",
          title: `${s.Title} (${s.Category})`,
          description: `Trivy secret detector matched ${s.RuleID}.`,
          ruleId: `trivy-secret/${s.RuleID}`,
          cwe: ["CWE-798"],
          location: {
            file: targetFile,
            line: s.StartLine,
            endLine: s.EndLine,
            snippet: truncate(s.Match, 200),
          },
        }));
      }
    }

    await ctx.progress(1, `${count} trivy findings`);
  },
};

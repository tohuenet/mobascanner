/**
 * Cloud audit adapters — Scout Suite + ScubaGear.
 *
 *   - source.scout-suite : multi-cloud (AWS / Azure / GCP / Oracle / AliBaba)
 *                          posture audit. Inherits CLI auth.
 *   - source.scubagear   : Microsoft 365 (Azure AD / Exchange / SharePoint /
 *                          Teams / Power Platform) compliance for CISA SCuBA.
 */

import path from "node:path";
import os from "node:os";
import { promises as fs } from "node:fs";
import { randomUUID } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli } from "../common";

const SEV_MAP: Record<string, "critical"|"high"|"medium"|"low"|"info"> = {
  CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "info",
  Pass: "info", Fail: "high", Warning: "medium", "N/A": "info",
};

// ─────────────────────────── Scout Suite ─────────────────────────────
export const scoutSuiteScanner: Scanner = {
  id: "source.scout-suite",
  name: "Scout Suite (multi-cloud posture)",
  kind: "source",
  description: "NCC Group's Scout Suite — AWS / Azure / GCP / Oracle / AliBaba security posture audit. Inherits CLI auth (env / IAM / SDK).",
  defaultEnabled: false,
  async tool() {
    const v = await detectCli("scout", "--version");
    return {
      id: "source.scout-suite", name: "Scout Suite", kind: "source", backend: "cli",
      cliCommand: "scout", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`pip install scoutsuite`",
      upstream: "https://github.com/nccgroup/ScoutSuite", license: "GPL-2.0",
      description: "Multi-cloud posture audit.",
    };
  },
  async run(ctx) {
    const v = await detectCli("scout", "--version");
    if (!v) { await ctx.log("warn", "scout not found"); return; }
    const provider = (ctx.options.provider as string) ?? "aws";
    const reportDir = path.join(os.tmpdir(), `scout-${randomUUID()}`);
    const r = await runCli("scout", [provider, "--report-dir", reportDir, "--no-browser", "--quiet"], { signal: ctx.signal, timeoutMs: 60 * 60 * 1000 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    // Scout writes JS files; the actual JSON is at scoutsuite-results/scoutsuite_results_<provider>-<acct>.js
    let resultsDir;
    try { resultsDir = path.join(reportDir, "scoutsuite-results"); await fs.access(resultsDir); }
    catch { return; }
    const files = (await fs.readdir(resultsDir)).filter((f) => f.endsWith(".js"));
    let n = 0;
    for (const f of files) {
      const raw = await fs.readFile(path.join(resultsDir, f), "utf8");
      // Strip the `scoutsuite_results = ` prefix to get pure JSON.
      const json = raw.replace(/^[^=]+=\s*/, "").replace(/;?\s*$/, "");
      let parsed: { services?: Record<string, { findings?: Record<string, { description: string; level: string; flagged_items?: number; references?: string[]; remediation?: string }> }> };
      try { parsed = JSON.parse(json); } catch { continue; }
      for (const [serviceName, svc] of Object.entries(parsed.services ?? {})) {
        for (const [findKey, find] of Object.entries(svc.findings ?? {})) {
          if ((find.flagged_items ?? 0) === 0) continue;
          n++;
          await ctx.emit(draft({
            severity: SEV_MAP[find.level] ?? "medium", confidence: "high",
            title: `Scout Suite: ${serviceName} — ${find.description}`,
            description: find.description,
            ruleId: `scout-suite/${serviceName}/${findKey}`,
            location: { file: `${provider}/${serviceName}` },
            evidence: { flaggedItems: find.flagged_items },
            remediation: find.remediation,
            references: find.references,
          }));
        }
      }
    }
    await fs.rm(reportDir, { recursive: true, force: true }).catch(() => {});
    await ctx.progress(1, `${n} Scout Suite findings`);
  },
};

// ─────────────────────────── ScubaGear ─────────────────────────────
export const scubaGearScanner: Scanner = {
  id: "source.scubagear",
  name: "ScubaGear (M365 / SCuBA)",
  kind: "source",
  description: "CISA's ScubaGear — Microsoft 365 baseline compliance audit (CISA SCuBA). PowerShell module — caller must `Connect-MgGraph` first.",
  defaultEnabled: false,
  async tool() {
    const v = await detectCli("pwsh", "-Version").catch(() => null);
    return {
      id: "source.scubagear", name: "ScubaGear", kind: "source", backend: "cli",
      cliCommand: "pwsh", cliVersionArg: "-Version",
      status: v ? "available" : "missing", detectedVersion: typeof v === "string" ? v : undefined,
      installHint: "Install PowerShell 7 + ScubaGear module: `Install-Module -Name ScubaGear`",
      upstream: "https://github.com/cisagov/ScubaGear", license: "Apache-2.0",
      description: "CISA SCuBA M365 baseline.",
    };
  },
  async run(ctx) {
    const v = await detectCli("pwsh", "-Version");
    if (!v) { await ctx.log("warn", "pwsh not found"); return; }
    const products = (ctx.options.products as string) ?? "aad,defender,exo,powerplatform,sharepoint,teams";
    const out = path.join(os.tmpdir(), `scubagear-${randomUUID()}`);
    await fs.mkdir(out, { recursive: true });
    const cmd = `Invoke-SCuBA -ProductNames ${products.split(",").map((p) => `'${p}'`).join(",")} -OutPath '${out.replace(/\\/g, "\\\\")}'`;
    const r = await runCli("pwsh", ["-NoProfile", "-Command", cmd], { signal: ctx.signal, timeoutMs: 60 * 60 * 1000 });
    if (r.spawnError) return;
    // ScubaGear writes to <OutPath>/M365BaselineConformance/<timestamp>/...
    let conformanceDir;
    try {
      const baseline = path.join(out, "M365BaselineConformance");
      const subdirs = await fs.readdir(baseline);
      conformanceDir = path.join(baseline, subdirs[0]);
    } catch { return; }
    const files = (await fs.readdir(conformanceDir).catch(() => [])).filter((f) => f.endsWith(".json"));
    let n = 0;
    for (const f of files) {
      const json = await fs.readFile(path.join(conformanceDir, f), "utf8").catch(() => null);
      if (!json) continue;
      let parsed: { Results?: Array<{ Control: string; Requirement: string; Result: string; Details?: string }> };
      try { parsed = JSON.parse(json); } catch { continue; }
      for (const res of parsed.Results ?? []) {
        if (res.Result === "Pass") continue;
        n++;
        await ctx.emit(draft({
          severity: SEV_MAP[res.Result] ?? "medium", confidence: "high",
          title: `ScubaGear ${res.Control}: ${res.Requirement}`,
          description: res.Details ?? res.Requirement,
          ruleId: `scubagear/${res.Control}`,
          location: { file: f },
          evidence: { result: res.Result },
        }));
      }
    }
    await fs.rm(out, { recursive: true, force: true }).catch(() => {});
    await ctx.progress(1, `${n} ScubaGear findings`);
  },
};

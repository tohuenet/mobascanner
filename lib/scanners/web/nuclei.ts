/**
 * nuclei adapter — wraps the ProjectDiscovery `nuclei` CLI.
 *
 * Strategy:
 *   - Detect if `nuclei` is on PATH at scan time (`tool()` returns "missing"
 *     with an install hint when not).
 *   - Run with `-jsonl -silent -nh -duc -nc -severity ...` and stream NDJSON
 *     line-by-line. Each line maps directly to one Finding.
 *   - The user can pin a templates directory via `options.templates` (defaults
 *     to `~/.config/nuclei` which the CLI manages itself).
 *
 * Output contract reference: https://docs.projectdiscovery.io/tools/nuclei/running#output
 */

import path from "node:path";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, safeUrl } from "../common";

interface NucleiJson {
  "template-id"?: string;
  "template-url"?: string;
  info?: {
    name?: string;
    description?: string;
    severity?: string;
    classification?: { "cve-id"?: string[]; "cwe-id"?: string[]; "cvss-score"?: number };
    reference?: string[];
    tags?: string[];
  };
  type?: string;
  host?: string;
  "matched-at"?: string;
  "matcher-name"?: string;
  request?: string;
  response?: string;
  curl?: string;
}

const SEVERITY_MAP: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  unknown: "info",
};

export const nucleiScanner: Scanner = {
  id: "web.nuclei",
  name: "Nuclei",
  kind: "web",
  description: "ProjectDiscovery nuclei: template-driven scanner for thousands of CVEs, misconfigurations, and exposures. Runs only if `nuclei` is on PATH.",
  defaultEnabled: false, // off by default — needs an external binary

  async tool() {
    const v = await detectCli("nuclei", "-version");
    return {
      id: "web.nuclei",
      name: "Nuclei",
      kind: "web",
      backend: "cli",
      cliCommand: "nuclei",
      cliVersionArg: "-version",
      status: v ? "available" : "missing",
      detectedVersion: v ?? undefined,
      installHint: "Download from https://github.com/projectdiscovery/nuclei/releases or `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`",
      upstream: "https://github.com/projectdiscovery/nuclei",
      license: "MIT",
      description: "ProjectDiscovery template-based vulnerability scanner.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) { await ctx.log("error", "invalid URL"); return; }

    const v = await detectCli("nuclei", "-version");
    if (!v) {
      await ctx.log("warn", "nuclei not found on PATH — skipping");
      return;
    }

    await ctx.log("info", `nuclei detected: ${v}`);
    await ctx.progress(0.05, "starting nuclei");

    const args = [
      "-target", url.toString(),
      "-jsonl",
      "-silent",
      "-nh",   // no header banner
      "-duc",  // disable update check
      "-nc",   // no color
      "-severity", "info,low,medium,high,critical",
      "-rate-limit", String(ctx.options.rateLimit ?? 50),
      "-timeout", String(ctx.options.timeout ?? 8),
    ];
    if (typeof ctx.options.templates === "string") {
      args.push("-t", path.resolve(ctx.options.templates));
    }
    if (typeof ctx.options.tags === "string") {
      args.push("-tags", ctx.options.tags);
    }

    let lineCount = 0;
    const result = await runCli("nuclei", args, {
      signal: ctx.signal,
      timeoutMs: 30 * 60 * 1000, // hard cap 30min
      onStdout: async (line) => {
        const trimmed = line.trim();
        if (!trimmed.startsWith("{")) return;
        let obj: NucleiJson;
        try { obj = JSON.parse(trimmed) as NucleiJson; }
        catch { return; }

        lineCount += 1;
        const sev = SEVERITY_MAP[(obj.info?.severity ?? "info").toLowerCase()] ?? "info";
        await ctx.emit(draft({
          severity: sev,
          confidence: "high",
          title: obj.info?.name ?? obj["template-id"] ?? "nuclei finding",
          description: obj.info?.description ?? "",
          ruleId: obj["template-id"],
          cve: obj.info?.classification?.["cve-id"],
          cwe: obj.info?.classification?.["cwe-id"],
          cvss: obj.info?.classification?.["cvss-score"],
          location: {
            url: obj["matched-at"] ?? obj.host ?? url.toString(),
            snippet: obj["matcher-name"],
          },
          evidence: {
            type: obj.type,
            request: obj.request,
            response: obj.response,
            curl: obj.curl,
            tags: obj.info?.tags,
          },
          references: obj.info?.reference,
        }));
      },
      onStderr: async (line) => {
        if (line.trim()) await ctx.log("info", line.trim());
      },
    });

    if (result.spawnError) {
      await ctx.log("error", `nuclei spawn failed: ${result.spawnError}`);
      return;
    }
    await ctx.progress(1, `nuclei done — ${lineCount} matches`);
  },
};

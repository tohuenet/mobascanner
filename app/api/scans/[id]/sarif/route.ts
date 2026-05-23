/**
 * GET /api/scans/[id]/sarif — export findings as SARIF 2.1.0.
 *
 * SARIF (Static Analysis Results Interchange Format) is the lingua franca
 * for GitHub Code Scanning, Azure DevOps, and most security dashboards.
 * Uploading the file to GitHub via `gh codeql upload` or the Code Scanning
 * REST API surfaces moba-scanner findings as repo-level alerts.
 */

import { NextResponse } from "next/server";
import { getScan, listFindings } from "@/lib/store";
import type { Finding } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const LEVEL_MAP: Record<string, "error" | "warning" | "note"> = {
  critical: "error", high: "error", medium: "warning", low: "note", info: "note",
};
const SEVERITY_NUMERIC: Record<string, number> = {
  critical: 9.5, high: 8.0, medium: 5.0, low: 3.0, info: 0.5,
};

function toSarif(scan: { id: string; target: { value: string } }, findings: Finding[]): object {
  const ruleMap = new Map<string, { id: string; name?: string; shortDescription: string; fullDescription: string; properties: { "security-severity": string; tags: string[] } }>();
  for (const f of findings) {
    const id = f.ruleId ?? f.scannerId;
    if (!ruleMap.has(id)) {
      ruleMap.set(id, {
        id,
        name: f.scannerName,
        shortDescription: f.title,
        fullDescription: f.description ?? f.title,
        properties: {
          "security-severity": String(SEVERITY_NUMERIC[f.severity] ?? 1),
          tags: ["security", ...(f.cwe ?? []).map((c) => c.toLowerCase()), ...(f.owasp ?? []).map((c) => c.replace(/[: ]/g, "").toLowerCase())],
        },
      });
    }
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "moba-scanner",
          version: "0.1.0",
          informationUri: "https://github.com/local/moba-scanner",
          rules: [...ruleMap.values()].map((r) => ({
            id: r.id,
            name: r.name,
            shortDescription: { text: r.shortDescription.slice(0, 200) },
            fullDescription: { text: r.fullDescription.slice(0, 1000) },
            defaultConfiguration: { level: "warning" },
            properties: r.properties,
          })),
        },
      },
      properties: { target: scan.target.value, scanId: scan.id },
      results: findings.map((f) => ({
        ruleId: f.ruleId ?? f.scannerId,
        level: LEVEL_MAP[f.severity] ?? "note",
        message: { text: f.description?.slice(0, 2000) || f.title },
        locations: [
          f.location.file
            ? {
                physicalLocation: {
                  artifactLocation: { uri: f.location.file },
                  region: {
                    startLine: f.location.line ?? 1,
                    endLine: f.location.endLine ?? f.location.line ?? 1,
                    startColumn: f.location.column ?? 1,
                  },
                },
              }
            : {
                physicalLocation: { artifactLocation: { uri: f.location.url ?? "unknown" } },
              },
        ],
        properties: {
          "security-severity": String(SEVERITY_NUMERIC[f.severity] ?? 1),
          cwe: f.cwe,
          cve: f.cve,
          owasp: f.owasp,
          confidence: f.confidence,
          scanner: f.scannerId,
        },
      })),
    }],
  };
}

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/sarif">) {
  const { id } = await ctx.params;
  const scan = await getScan(id);
  if (!scan) return NextResponse.json({ error: "not found" }, { status: 404 });
  const findings = await listFindings(id);
  const sarif = toSarif(scan, findings);
  return new NextResponse(JSON.stringify(sarif, null, 2), {
    headers: {
      "Content-Type": "application/sarif+json",
      "Content-Disposition": `attachment; filename="moba-${id}.sarif"`,
    },
  });
}

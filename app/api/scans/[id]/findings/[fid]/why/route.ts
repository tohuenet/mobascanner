/**
 * GET /api/scans/[id]/findings/[fid]/why
 *
 * Returns a structured "why is this finding here" explanation:
 *   - which scanner detected it
 *   - what payload / probe was sent
 *   - what marker matched
 *   - related compliance controls
 *   - duplicate findings collapsed into this one
 *
 * Useful for triage: in 30 seconds a security engineer sees the full
 * provenance of every finding without grepping through evidence blobs.
 */

import { NextResponse } from "next/server";
import { listFindings } from "@/lib/store";
import { buildReport, type Framework } from "@/lib/compliance/mapping";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/findings/[fid]/why">) {
  const { id, fid } = await ctx.params;
  const findings = await listFindings(id);
  const f = findings.find((x) => x.id === fid);
  if (!f) return NextResponse.json({ error: "not found" }, { status: 404 });

  // Compliance mapping — show every framework + control hit by this CWE/OWASP set.
  const FRAMEWORKS: Framework[] = ["PCI-DSS", "SOC2", "HIPAA", "ISO27001"];
  const compliance: Record<string, string[]> = {};
  for (const fw of FRAMEWORKS) {
    const r = buildReport(fw, [f]);
    compliance[fw] = r.controls.map((c) => `${c.control} — ${c.description}`);
  }

  // Provenance: pull duplicate scanner ids if dedup merged this finding.
  const dupIds = (f.evidence as { duplicates?: Array<{ ruleId?: string; scanner?: string; title?: string }> } | undefined)?.duplicates ?? [];
  const seenByScanners = (f.evidence as { seenByScanners?: string[] } | undefined)?.seenByScanners ?? [f.scannerName];

  return NextResponse.json({
    finding: { id: f.id, title: f.title, severity: f.severity, confidence: f.confidence },
    detected_by: f.scannerName,
    rule_id: f.ruleId,
    primary_marker: extractMarker(f),
    classification: { cwe: f.cwe ?? [], cve: f.cve ?? [], owasp: f.owasp ?? [], cvss: f.cvss },
    location: f.location,
    seen_by_scanners: seenByScanners,
    duplicate_findings: dupIds,
    compliance,
    triage: f.triage,
    remediation: f.remediation,
    references: f.references,
  });
}

function extractMarker(f: { evidence?: Record<string, unknown> }): string {
  if (!f.evidence) return "(no evidence)";
  const e = f.evidence as Record<string, unknown>;
  if (typeof e.payload === "string") return `payload: ${e.payload}`;
  if (typeof e.match === "string") return `match: ${e.match}`;
  if (typeof e.snippet === "string") return `snippet: ${e.snippet.slice(0, 100)}`;
  if (typeof e.canary === "string") return `canary: ${e.canary}`;
  if (typeof e.value === "string") return `value: ${e.value}`;
  return JSON.stringify(e).slice(0, 200);
}

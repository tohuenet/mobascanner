/**
 * GET /api/scans/[id]/compliance/[framework]
 * framework ∈ { PCI-DSS, SOC2, HIPAA, ISO27001 }
 *
 * Returns the framework's controls grouped by findings, plus controls
 * that have NO findings (uncovered → either secure or untested).
 */

import { NextResponse } from "next/server";
import { listFindings } from "@/lib/store";
import { buildReport, type Framework } from "@/lib/compliance/mapping";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const VALID: Framework[] = ["PCI-DSS", "SOC2", "HIPAA", "ISO27001"];

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/compliance/[framework]">) {
  const { id, framework } = await ctx.params;
  if (!VALID.includes(framework as Framework)) {
    return NextResponse.json({ error: `framework must be one of ${VALID.join(", ")}` }, { status: 400 });
  }
  const findings = await listFindings(id);
  const report = buildReport(framework as Framework, findings);
  return NextResponse.json(report);
}

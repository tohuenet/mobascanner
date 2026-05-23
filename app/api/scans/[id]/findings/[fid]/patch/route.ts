/**
 * POST /api/scans/[id]/findings/[fid]/patch
 *
 * Generates an LLM-suggested patch for a single finding. Returns
 *   { kind, patch, explanation, confidence, warnings, usage? }
 *
 * Never writes to disk — caller decides whether to apply.
 */

import { NextResponse } from "next/server";
import { listFindings } from "@/lib/store";
import { generatePatch } from "@/lib/triage/patcher";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(_req: Request, ctx: RouteContext<"/api/scans/[id]/findings/[fid]/patch">) {
  const { id, fid } = await ctx.params;
  const findings = await listFindings(id);
  const f = findings.find((x) => x.id === fid);
  if (!f) return NextResponse.json({ error: "not found" }, { status: 404 });
  const result = await generatePatch(f);
  if (result.error) return NextResponse.json(result, { status: result.error.includes("not set") ? 400 : 502 });
  return NextResponse.json(result);
}

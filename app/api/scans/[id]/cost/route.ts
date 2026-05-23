/**
 * GET /api/scans/[id]/cost — per-scanner cost breakdown for a scan.
 * HTTP requests, bytes out, latency, LLM tokens (for triage / agentic).
 */

import { NextResponse } from "next/server";
import { getCostReport } from "@/lib/engine/cost-tracker";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/cost">) {
  const { id } = await ctx.params;
  const report = getCostReport(id);
  const totals = report.reduce((acc, r) => ({
    httpRequests: acc.httpRequests + r.httpRequests,
    bytesOut: acc.bytesOut + r.bytesOut,
    ms: acc.ms + r.ms,
    llmInputTokens: acc.llmInputTokens + r.llmInputTokens,
    llmOutputTokens: acc.llmOutputTokens + r.llmOutputTokens,
  }), { httpRequests: 0, bytesOut: 0, ms: 0, llmInputTokens: 0, llmOutputTokens: 0 });
  return NextResponse.json({ scanId: id, perScanner: report, totals });
}

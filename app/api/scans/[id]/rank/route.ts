/**
 * GET /api/scans/[id]/rank — ranked top-N findings by ROI.
 * Query: ?limit=10 (default 10, max 100)
 */

import { NextResponse } from "next/server";
import { listFindings } from "@/lib/store";
import { rankFindings } from "@/lib/triage/ranker";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request, ctx: RouteContext<"/api/scans/[id]/rank">) {
  const { id } = await ctx.params;
  const url = new URL(req.url);
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit")) || 10, 1), 100);
  const findings = await listFindings(id);
  const ranked = rankFindings(findings).slice(0, limit);
  return NextResponse.json({
    total: findings.length,
    ranked: ranked.map((r) => ({
      rank: r.rank,
      score: Math.round(r.score),
      reason: r.reason,
      id: r.id,
      severity: r.finding.severity,
      title: r.finding.title,
      ruleId: r.finding.ruleId,
      location: r.finding.location,
    })),
  });
}

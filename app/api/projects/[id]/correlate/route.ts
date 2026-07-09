/**
 * /api/projects/[id]/correlate
 *   POST → run the correlation pass over the project's member scans.
 *
 * Idempotent: re-running rewrites `data/projects/<id>/findings.jsonl` and never
 * duplicates. Works with ANTHROPIC_API_KEY unset (LLM enrichment is skipped).
 */

import { NextResponse, type NextRequest } from "next/server";
import { correlateProject } from "@/lib/correlation/engine";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(_req: NextRequest, ctx: RouteContext<"/api/projects/[id]/correlate">) {
  const { id } = await ctx.params;
  try {
    const findings = await correlateProject(id);
    return NextResponse.json({ count: findings.length, findings });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /not found/i.test(msg) ? 404 : 500;
    return NextResponse.json({ error: msg }, { status });
  }
}

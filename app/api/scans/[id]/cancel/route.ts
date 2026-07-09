/**
 * POST /api/scans/[id]/cancel
 *
 * Aborts a running scan via the registered AbortController. Idempotent:
 * cancelling a scan that already finished is a no-op (returns ok:true,
 * cancelled:false so the UI can distinguish).
 *
 * Unlike DELETE on /api/scans/[id], this leaves the scan + findings intact —
 * just stops the work. Use DELETE when the goal is to throw the scan away.
 */

import { NextResponse } from "next/server";
import { cancelScan } from "@/lib/engine/runner";
import "@/lib/scanners";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(_req: Request, ctx: RouteContext<"/api/scans/[id]/cancel">) {
  const { id } = await ctx.params;
  const cancelled = cancelScan(id);
  return NextResponse.json({ ok: true, cancelled });
}

/**
 * /api/scans/[id]
 *   GET    → full Scan + its findings (paginated by ?limit & ?offset)
 *   DELETE → remove the scan + artifacts
 */

import { NextResponse } from "next/server";
import { deleteScan, getScan, listFindings } from "@/lib/store";
import { cancelScan } from "@/lib/engine/runner";
import "@/lib/scanners";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]">) {
  const { id } = await ctx.params;
  const scan = await getScan(id);
  if (!scan) return NextResponse.json({ error: "not found" }, { status: 404 });
  const findings = await listFindings(id);
  return NextResponse.json({ scan, findings });
}

export async function DELETE(_req: Request, ctx: RouteContext<"/api/scans/[id]">) {
  const { id } = await ctx.params;
  cancelScan(id); // best-effort
  await deleteScan(id);
  return NextResponse.json({ ok: true });
}

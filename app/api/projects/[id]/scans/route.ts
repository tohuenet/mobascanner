/**
 * /api/projects/[id]/scans
 *   POST   → attach a scan { scanId } (dedupes; pulls kind+target from the scan)
 *   DELETE → detach a scan (scanId from ?scanId= or JSON body)
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { addScanToProject, removeScanFromProject } from "@/lib/projects/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const BodySchema = z.object({ scanId: z.string().min(1).max(200) });

export async function POST(req: NextRequest, ctx: RouteContext<"/api/projects/[id]/scans">) {
  const { id } = await ctx.params;
  const body = await req.json().catch(() => null);
  const parsed = BodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "invalid body", details: parsed.error.flatten() }, { status: 400 });
  }
  try {
    const project = await addScanToProject(id, parsed.data.scanId);
    return NextResponse.json({ project });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: msg }, { status: 404 });
  }
}

export async function DELETE(req: NextRequest, ctx: RouteContext<"/api/projects/[id]/scans">) {
  const { id } = await ctx.params;
  const fromQuery = new URL(req.url).searchParams.get("scanId");
  const body = fromQuery ? null : await req.json().catch(() => null);
  const scanId = fromQuery ?? (body && typeof body.scanId === "string" ? body.scanId : null);
  if (!scanId) {
    return NextResponse.json({ error: "scanId required (query ?scanId= or body)" }, { status: 400 });
  }
  try {
    const project = await removeScanFromProject(id, scanId);
    return NextResponse.json({ project });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: msg }, { status: 404 });
  }
}

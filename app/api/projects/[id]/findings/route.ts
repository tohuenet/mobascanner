/**
 * /api/projects/[id]/findings
 *   GET → the project's persisted correlated findings (does not re-run the pass).
 */

import { NextResponse, type NextRequest } from "next/server";
import { getProject, listProjectFindings } from "@/lib/projects/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: NextRequest, ctx: RouteContext<"/api/projects/[id]/findings">) {
  const { id } = await ctx.params;
  const project = await getProject(id);
  if (!project) return NextResponse.json({ error: "not found" }, { status: 404 });
  const findings = await listProjectFindings(id);
  return NextResponse.json({ findings });
}

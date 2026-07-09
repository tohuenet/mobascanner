/**
 * /api/projects/[id]
 *   GET    → the Project
 *   PATCH  → update name / targets / meta
 *   DELETE → remove the project + its artifacts
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { deleteProject, getProject, updateProject } from "@/lib/projects/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const PatchSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  targets: z
    .object({
      host: z.string().max(400).optional(),
      repo: z.string().max(400).optional(),
    })
    .optional(),
  meta: z.record(z.string(), z.unknown()).optional(),
});

export async function GET(_req: NextRequest, ctx: RouteContext<"/api/projects/[id]">) {
  const { id } = await ctx.params;
  const project = await getProject(id);
  if (!project) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ project });
}

export async function PATCH(req: NextRequest, ctx: RouteContext<"/api/projects/[id]">) {
  const { id } = await ctx.params;
  const body = await req.json().catch(() => null);
  const parsed = PatchSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "invalid body", details: parsed.error.flatten() }, { status: 400 });
  }
  const project = await updateProject(id, parsed.data);
  if (!project) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ project });
}

export async function DELETE(_req: NextRequest, ctx: RouteContext<"/api/projects/[id]">) {
  const { id } = await ctx.params;
  await deleteProject(id);
  return NextResponse.json({ ok: true });
}

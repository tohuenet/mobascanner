/**
 * /api/projects
 *   GET  → list of projects (index entries)
 *   POST → create a project (name + optional canonical targets)
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { createProject, listProjects } from "@/lib/projects/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CreateSchema = z.object({
  name: z.string().min(1).max(200),
  targets: z
    .object({
      host: z.string().max(400).optional(),
      repo: z.string().max(400).optional(),
    })
    .optional(),
  meta: z.record(z.string(), z.unknown()).optional(),
});

export async function GET() {
  const items = await listProjects();
  return NextResponse.json({ items });
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = CreateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "invalid body", details: parsed.error.flatten() }, { status: 400 });
  }
  const project = await createProject(parsed.data);
  return NextResponse.json({ project }, { status: 201 });
}

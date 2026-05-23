import { NextResponse } from "next/server";
import { deleteSchedule, updateSchedule } from "@/lib/schedule/scheduler";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function PATCH(req: Request, ctx: RouteContext<"/api/schedules/[id]">) {
  const { id } = await ctx.params;
  const body = await req.json().catch(() => ({}));
  const updated = await updateSchedule(id, body);
  if (!updated) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json(updated);
}

export async function DELETE(_req: Request, ctx: RouteContext<"/api/schedules/[id]">) {
  const { id } = await ctx.params;
  await deleteSchedule(id);
  return NextResponse.json({ ok: true });
}

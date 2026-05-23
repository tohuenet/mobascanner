/**
 * /api/schedules
 *   GET  → list configured schedules
 *   POST → create a new schedule
 */

import { NextResponse, type NextRequest } from "next/server";
import { ScheduleSchema, createSchedule, listSchedules, startScheduler } from "@/lib/schedule/scheduler";
import { z } from "zod";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CREATE = ScheduleSchema.omit({ id: true });

export async function GET() {
  startScheduler();
  return NextResponse.json({ items: await listSchedules() });
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = CREATE.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid schedule", details: parsed.error.flatten() }, { status: 400 });
  if (!parsed.data.intervalMinutes && !parsed.data.dailyAt) {
    return NextResponse.json({ error: "must specify intervalMinutes or dailyAt" }, { status: 400 });
  }
  startScheduler();
  const schedule = await createSchedule(parsed.data);
  return NextResponse.json(schedule, { status: 201 });
}

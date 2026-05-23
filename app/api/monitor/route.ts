/**
 * /api/monitor
 *   GET    → list monitor targets
 *   POST   → add a target { apex, notes }
 *   PATCH  → trigger a sweep for all (or a specific apex via ?apex=)
 */

import { NextResponse, type NextRequest } from "next/server";
import { addTarget, listTargets, sweep, sweepAll } from "@/lib/monitor/continuous";
import { z } from "zod";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ items: await listTargets() });
}

const ADD = z.object({ apex: z.string().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/), notes: z.string().optional() });

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = ADD.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid body", details: parsed.error.flatten() }, { status: 400 });
  return NextResponse.json(await addTarget(parsed.data));
}

export async function PATCH(req: NextRequest) {
  const url = new URL(req.url);
  const apex = url.searchParams.get("apex");
  if (apex) {
    const t = (await listTargets()).find((x) => x.apex === apex);
    if (!t) return NextResponse.json({ error: "apex not registered" }, { status: 404 });
    return NextResponse.json(await sweep(t));
  }
  return NextResponse.json({ results: await sweepAll() });
}

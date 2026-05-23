/**
 * POST /api/auth-record/start { profileId, url } — open Chromium for login.
 * Requires `playwright-core` + chromium binary (`npx playwright install chromium`).
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { startRecording, listSessions } from "@/lib/auth/playwright-recorder";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const REQ = z.object({ profileId: z.string().min(1).max(64), url: z.string().url() });

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = REQ.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid body" }, { status: 400 });
  try { return NextResponse.json(await startRecording(parsed.data.profileId, parsed.data.url)); }
  catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: msg, hint: msg.includes("chromium") ? "Run `npx playwright install chromium`" : undefined }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({ activeSessions: listSessions() });
}

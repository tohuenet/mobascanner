import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { saveRecording, cancelRecording } from "@/lib/auth/playwright-recorder";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const REQ = z.object({ profileId: z.string().min(1).max(64) });

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = REQ.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid body" }, { status: 400 });
  try { return NextResponse.json(await saveRecording(parsed.data.profileId)); }
  catch (e) { return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 }); }
}

export async function DELETE(req: NextRequest) {
  const url = new URL(req.url);
  const profileId = url.searchParams.get("profileId");
  if (!profileId) return NextResponse.json({ error: "?profileId= required" }, { status: 400 });
  await cancelRecording(profileId);
  return NextResponse.json({ ok: true });
}

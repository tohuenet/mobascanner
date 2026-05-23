/**
 * POST /api/share { scanId, scope, findingId?, ttlSeconds? }
 * Returns: { token, url }
 *
 * Receiver: GET /share/<token> via app/share/[token]/page.tsx (read-only).
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { signShare } from "@/lib/share/jwt";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const REQ = z.object({
  scanId: z.string().uuid(),
  scope: z.enum(["scan", "finding"]),
  findingId: z.string().uuid().optional(),
  ttlSeconds: z.number().min(60).max(60 * 60 * 24 * 30).optional(),
});

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = REQ.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid body" }, { status: 400 });
  if (parsed.data.scope === "finding" && !parsed.data.findingId) {
    return NextResponse.json({ error: "findingId required when scope=finding" }, { status: 400 });
  }
  try {
    const token = await signShare(parsed.data);
    const proto = req.headers.get("x-forwarded-proto") ?? "http";
    const host = req.headers.get("host") ?? "localhost:3000";
    return NextResponse.json({ token, url: `${proto}://${host}/share/${token}` });
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 });
  }
}

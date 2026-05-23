/**
 * GET /api/presets — list scanner presets.
 * Used by UI to populate "Quick posture / Bug-bounty / Full pentest / Compliance"
 * buttons on the scan-creation form.
 */

import { NextResponse } from "next/server";
import { PRESETS } from "@/lib/presets";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ presets: PRESETS });
}

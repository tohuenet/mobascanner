/**
 * GET /api/setup/auth-record/status
 *
 * Returns the readiness of the browser-capture feature so the UI can render
 * a self-serve checklist (vault key configured, Chromium binary installed,
 * install in progress + recent log).
 */

import { NextResponse } from "next/server";
import { readSetupStatus } from "@/lib/auth/setup-status";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    return NextResponse.json(await readSetupStatus());
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}

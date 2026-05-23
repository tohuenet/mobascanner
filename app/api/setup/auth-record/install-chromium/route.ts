/**
 * POST /api/setup/auth-record/install-chromium
 *
 * Kicks off a background `playwright-core install chromium` if Chromium isn't
 * already installed and isn't already being installed. Returns the same
 * payload as the status endpoint so the UI can show progress immediately.
 *
 * The actual streaming is done via polling /status — keeps the protocol
 * simple and avoids standing up an SSE channel for a one-off install.
 */

import { NextResponse } from "next/server";
import { startChromiumInstall } from "@/lib/auth/setup-status";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST() {
  try {
    return NextResponse.json(await startChromiumInstall(), { status: 202 });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}

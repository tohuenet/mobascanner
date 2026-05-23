/**
 * /api/tools — list every registered scanner with live availability info.
 * Used by the scan builder UI to show "missing CLI" hints next to each toggle.
 */

import { NextResponse } from "next/server";
import { listScanners } from "@/lib/engine/registry";
import "@/lib/scanners";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const scanners = listScanners();
  const tools = await Promise.all(scanners.map((s) => s.tool().then((t) => ({
    ...t,
    defaultEnabled: s.defaultEnabled ?? false,
  }))));
  return NextResponse.json({ tools });
}

/**
 * GET /api/scans/[id]/har — exports captured traffic as a HAR 1.2 document.
 * Drop into Burp / Postman / Charles for inspection.
 */

import { NextResponse } from "next/server";
import { exportHar } from "@/lib/web/traffic-capture";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/har">) {
  const { id } = await ctx.params;
  const har = await exportHar(id);
  return new NextResponse(har, {
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="moba-${id}.har"`,
    },
  });
}

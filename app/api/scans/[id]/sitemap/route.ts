/**
 * GET /api/scans/[id]/sitemap
 *
 * Returns the SiteMap the deep crawler built for this scan. 404 when the scan
 * didn't include `web.crawler` or the crawler hasn't finished writing the
 * file yet (the SiteMapTab UI handles that case explicitly).
 */

import { NextResponse } from "next/server";
import { loadSiteMap } from "@/lib/web/sitemap";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/sitemap">) {
  const { id } = await ctx.params;
  const map = await loadSiteMap(id);
  if (!map) {
    return NextResponse.json({ error: "sitemap not found for scan" }, { status: 404 });
  }
  return NextResponse.json(map);
}

/**
 * POST /api/live-browser/check
 *   { cdpUrl, url? } → attempt to attach to the user's Chrome over CDP and
 *   report whether it worked, how many cookies it holds (total + scoped to the
 *   target), and its User-Agent. Powers the "Test connection" button on the
 *   scan-setup page. Read-only: it never opens tabs in the user's browser.
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { acquireBrowser, releaseBrowser } from "@/lib/web/browser";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const Schema = z.object({
  cdpUrl: z.string().min(1).max(2048),
  url: z.string().optional(),
});

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = Schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ ok: false, error: "invalid body" }, { status: 400 });
  }
  const { cdpUrl, url } = parsed.data;

  const acq = await acquireBrowser({ cdpUrl }).catch((e) => {
    return { error: e instanceof Error ? e.message : String(e) } as const;
  });
  if ("error" in acq) {
    return NextResponse.json({
      ok: false,
      error: `could not attach: ${acq.error}. Launch Chrome with --remote-debugging-port and check the endpoint.`,
    });
  }
  if (!acq.attached) {
    await releaseBrowser(acq, false);
    return NextResponse.json({ ok: false, error: "endpoint is not an attachable browser" });
  }

  try {
    const context = acq.browser.contexts()[0];
    let cookieCount = 0;
    let targetCookies = 0;
    let userAgent: string | null = null;
    if (context) {
      try { cookieCount = (await context.cookies()).length; } catch { /* ignore */ }
      if (url) { try { targetCookies = (await context.cookies(url)).length; } catch { /* ignore */ } }
      const pages = context.pages();
      if (pages.length > 0) {
        userAgent = await pages[0].evaluate(() => navigator.userAgent).catch(() => null);
      }
    }
    return NextResponse.json({ ok: true, cookieCount, targetCookies, userAgent });
  } catch (e) {
    return NextResponse.json({ ok: false, error: e instanceof Error ? e.message : String(e) });
  } finally {
    // Never close the user's browser.
    await releaseBrowser(acq, false);
  }
}

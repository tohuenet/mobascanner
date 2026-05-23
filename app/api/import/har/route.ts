/**
 * POST /api/import/har — accepts a HAR file (Chrome / Firefox export, or
 * Burp / mitmproxy export) and creates a synthetic SiteMap from it. The
 * caller can then start a scan with `kind=web` and the resulting scanId
 * already has a populated sitemap, skipping the crawl phase.
 *
 * Request:
 *   { harJson: <stringified HAR>, target: { value, type: "url" } }
 *
 * Response:
 *   { scanId, pages: <count>, forms: <count> }
 *
 * Why this is useful: many real apps require an authenticated session that
 * the scanner can't replicate. The user logs in via their own browser, exports
 * the HAR, uploads it — the scanner now sees every URL/form/cookie the user
 * touched, including authenticated ones.
 */

import { NextResponse, type NextRequest } from "next/server";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { createScan } from "@/lib/store";
import { makeScan } from "@/lib/engine/runner";
import { saveSiteMap, type SiteMap, type SiteMapForm, type SiteMapPage } from "@/lib/web/sitemap";
import "@/lib/scanners";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const HAR_PAGE = z.object({
  request: z.object({
    method: z.string(),
    url: z.string(),
    headers: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
    cookies: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
    postData: z.object({
      mimeType: z.string().optional(),
      params: z.array(z.object({ name: z.string(), value: z.string().optional() })).optional(),
      text: z.string().optional(),
    }).optional(),
  }),
  response: z.object({
    status: z.number(),
    statusText: z.string().optional(),
    headers: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
    cookies: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
    content: z.object({ mimeType: z.string().optional(), size: z.number().optional() }).optional(),
  }),
});

const HAR_SCHEMA = z.object({ log: z.object({ entries: z.array(HAR_PAGE) }) });

const REQ = z.object({
  harJson: z.string(),
  target: z.object({ value: z.string(), type: z.literal("url") }),
});

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = REQ.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid body", details: parsed.error.flatten() }, { status: 400 });

  let har;
  try { har = HAR_SCHEMA.parse(JSON.parse(parsed.data.harJson)); }
  catch (e) { return NextResponse.json({ error: `invalid HAR: ${e instanceof Error ? e.message : String(e)}` }, { status: 400 }); }

  // Create a placeholder scan so the SiteMap has somewhere to live.
  const scanId = randomUUID();
  const targetOrigin = (() => { try { return new URL(parsed.data.target.value).origin; } catch { return ""; } })();

  const pages: SiteMapPage[] = [];
  const forms: SiteMapForm[] = [];
  const cookieJar: Record<string, string> = {};
  const apiHints: { url: string; source: string }[] = [];

  for (const e of har.log.entries) {
    const url = e.request.url;
    if (targetOrigin && !url.startsWith(targetOrigin)) continue;
    const headers: Record<string, string> = {};
    for (const h of e.response.headers ?? []) headers[h.name.toLowerCase()] = h.value;
    const setCookies = (e.response.headers ?? []).filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value);
    for (const c of e.response.cookies ?? []) cookieJar[c.name] = c.value;
    const ct = headers["content-type"] ?? "";
    pages.push({
      url,
      method: e.request.method.toUpperCase() as SiteMapPage["method"],
      status: e.response.status,
      contentType: ct,
      contentLength: e.response.content?.size,
      responseHeaders: headers,
      setCookies: setCookies.length ? setCookies : undefined,
      interestScore: 0.5 + (ct.includes("json") ? 0.4 : ct.includes("html") ? 0.1 : 0),
    });
    if (/\/(api|v\d|rest|graphql)\b/i.test(url)) apiHints.push({ url, source: "har" });

    // POST entries → synthesize a SiteMapForm so the form fuzzer / SQLi /
    // mass-assignment scanners can target them.
    if (e.request.method.toUpperCase() === "POST" && e.request.postData?.params) {
      forms.push({
        pageUrl: url,
        action: url,
        method: "POST",
        inputs: e.request.postData.params.map((p) => ({ name: p.name, type: "text", value: p.value })),
        looksLikeLogin: e.request.postData.params.some((p) => /password|passwd|pass$/i.test(p.name)),
        hasCsrfToken: e.request.postData.params.some((p) => /csrf|xsrf|token/i.test(p.name)),
      });
    }
  }

  const map: SiteMap = {
    scanId, origin: targetOrigin, pages, forms,
    apiHints: Array.from(new Map(apiHints.map((a) => [a.url, a])).values()),
    cookies: cookieJar, technologies: [], builtAt: Date.now(),
  };

  // Persist a stub scan in the index so the sitemap directory exists.
  const scan = makeScan({
    id: scanId, kind: "web",
    target: { value: parsed.data.target.value, type: "url" },
    selection: { enabled: ["web.crawler"] }, // ignored, just to populate
  });
  await createScan(scan);
  await saveSiteMap(map);

  return NextResponse.json({
    scanId, pages: pages.length, forms: forms.length, apiHints: apiHints.length,
    nextStep: `POST /api/scans with the imported sitemap by reusing scanId=${scanId} (or kicking off a fresh scan that consumes data/scans/${scanId}/sitemap.json).`,
  }, { status: 201 });
}

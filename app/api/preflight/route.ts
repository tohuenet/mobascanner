/**
 * /api/preflight — fast target reachability check before kicking off a scan.
 *
 * Without this, picking a dead URL (e.g. testphp.vulnweb.com after Acunetix
 * took it down) silently burns 5+ minutes running 70+ scanners against
 * nothing. A 7-second HEAD probe blocks that, with a "Scan anyway" escape
 * hatch on the client side.
 *
 * Tries HEAD first (cheap), falls back to a 1-byte ranged GET for servers
 * that 405 / 501 on HEAD. Returns status + duration so the UI can show
 * something useful.
 */

import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const TIMEOUT_MS = 7000;

interface PreflightResult {
  reachable: boolean;
  status?: number;
  finalUrl?: string;
  error?: string;
  durationMs: number;
}

async function probe(url: string, method: "HEAD" | "GET", signal: AbortSignal): Promise<Response> {
  const headers: Record<string, string> = { "user-agent": "moba-scanner/preflight" };
  if (method === "GET") headers["range"] = "bytes=0-0";
  return fetch(url, { method, headers, signal, redirect: "follow" });
}

export async function POST(req: Request) {
  let body: { url?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const url = typeof body.url === "string" ? body.url.trim() : "";
  if (!/^https?:\/\//i.test(url)) {
    return NextResponse.json<PreflightResult>({
      reachable: false,
      error: "URL must start with http:// or https://",
      durationMs: 0,
    });
  }

  const started = Date.now();
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    let res: Response;
    try {
      res = await probe(url, "HEAD", controller.signal);
      if (res.status === 405 || res.status === 501) {
        // Server refuses HEAD — retry with ranged GET.
        res = await probe(url, "GET", controller.signal);
      }
    } catch {
      // Some servers / proxies error out on HEAD entirely. Last-ditch GET.
      res = await probe(url, "GET", controller.signal);
    }
    clearTimeout(t);

    const ok = res.status >= 200 && res.status < 400;
    return NextResponse.json<PreflightResult>({
      reachable: ok,
      status: res.status,
      finalUrl: res.url,
      durationMs: Date.now() - started,
      ...(ok ? {} : { error: `HTTP ${res.status} ${res.statusText || ""}`.trim() }),
    });
  } catch (e) {
    clearTimeout(t);
    const msg = e instanceof Error ? e.message : String(e);
    // AbortError → 7s timeout. Surface a friendlier message.
    const friendly = /aborted|abort/i.test(msg)
      ? `No response within ${TIMEOUT_MS / 1000}s — host may be down or blocking traffic.`
      : msg;
    return NextResponse.json<PreflightResult>({
      reachable: false,
      error: friendly,
      durationMs: Date.now() - started,
    });
  }
}

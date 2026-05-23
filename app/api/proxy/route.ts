/**
 * /api/proxy
 *   POST   { port } → start TLS-MITM proxy via mockttp; returns { proxyPort, caUrl }
 *   DELETE          → stop proxy
 *   GET             → status
 *
 * After POST, the user downloads the CA from /api/proxy/ca, installs it as a
 * system / browser root, then configures HTTPS proxy → 127.0.0.1:<proxyPort>.
 * Every request flows into the active scan's HAR.
 */

import { NextResponse, type NextRequest } from "next/server";
import { startTlsProxy, stopTlsProxy, isTlsProxyRunning } from "@/lib/proxy/tls-mitm";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ running: isTlsProxyRunning() });
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const port = Number(body.port) || 8888;
  if (isTlsProxyRunning()) return NextResponse.json({ error: "already running" }, { status: 409 });
  try {
    const handle = await startTlsProxy(port);
    return NextResponse.json({
      ok: true,
      proxyPort: handle.proxyPort,
      caUrl: "/api/proxy/ca",
      hint: `Install /api/proxy/ca as a system root, then point your browser HTTPS proxy at 127.0.0.1:${handle.proxyPort}`,
    });
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 });
  }
}

export async function DELETE() {
  await stopTlsProxy();
  return NextResponse.json({ ok: true });
}

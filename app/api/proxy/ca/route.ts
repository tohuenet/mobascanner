/**
 * GET /api/proxy/ca — download the local MITM CA certificate (PEM).
 * Install as a system / browser root before using the TLS-MITM proxy.
 */

import { NextResponse } from "next/server";
import { getCaCertPem } from "@/lib/proxy/tls-mitm";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const pem = await getCaCertPem();
  if (!pem) return NextResponse.json({ error: "CA not generated yet — start the proxy first" }, { status: 404 });
  return new NextResponse(pem, {
    headers: {
      "Content-Type": "application/x-pem-file",
      "Content-Disposition": "attachment; filename=\"moba-mitm-ca.crt\"",
    },
  });
}

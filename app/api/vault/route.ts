/**
 * /api/vault
 *   GET            → list keys (no values)
 *   POST { k, v }  → put encrypted secret
 *   DELETE ?key=   → delete by key
 */

import { NextResponse, type NextRequest } from "next/server";
import { vaultDelete, vaultList, vaultPut } from "@/lib/vault/encrypted";
import { z } from "zod";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try { return NextResponse.json({ keys: await vaultList() }); }
  catch (e) { return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 }); }
}

const PUT = z.object({ k: z.string().min(1).max(128), v: z.string().min(1).max(64 * 1024) });

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = PUT.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid body" }, { status: 400 });
  try { await vaultPut(parsed.data.k, parsed.data.v); return NextResponse.json({ ok: true }); }
  catch (e) { return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 }); }
}

export async function DELETE(req: NextRequest) {
  const url = new URL(req.url);
  const key = url.searchParams.get("key");
  if (!key) return NextResponse.json({ error: "?key=… required" }, { status: 400 });
  await vaultDelete(key);
  return NextResponse.json({ ok: true });
}

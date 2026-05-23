/**
 * /api/scans
 *   GET  → list of scans (index entries)
 *   POST → create + kick off a scan, return its id immediately
 *
 * The runner intentionally fires-and-forgets; clients get progress via the
 * SSE stream at /api/scans/[id]/stream.
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { createScan, listScans } from "@/lib/store";
import { makeScan, runScan } from "@/lib/engine/runner";
import { profileToHeaders } from "@/lib/auth/profile";
import "@/lib/scanners"; // ensure adapters registered

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const TargetSchema = z.object({
  value: z.string().min(1),
  type: z.enum(["url", "git", "local", "archive"]),
  ref: z.string().optional(),
  auth: z.object({
    headers: z.record(z.string(), z.string()).optional(),
    cookies: z.record(z.string(), z.string()).optional(),
    bearerToken: z.string().optional(),
    basicAuth: z.object({ username: z.string(), password: z.string() }).optional(),
    /** Reference to a captured login profile in the vault. When set, the
     *  server resolves it to cookies via profileToHeaders() and merges those
     *  into auth.headers BEFORE the scan is persisted — the raw storageState
     *  never round-trips through the browser. */
    profileId: z.string().min(1).max(64).optional(),
  }).optional(),
});

const CreateSchema = z.object({
  kind: z.enum(["web", "source"]),
  target: TargetSchema,
  selection: z.object({
    enabled: z.array(z.string()),
    options: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
  }),
  meta: z.record(z.string(), z.unknown()).optional(),
});

export async function GET() {
  const items = await listScans();
  return NextResponse.json({ items });
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = CreateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "invalid body", details: parsed.error.flatten() }, { status: 400 });
  }

  // If the user picked a captured login profile, resolve it to cookies here
  // (server-side, vault never leaves the host) and bake them into auth.headers.
  // User-provided headers win on conflict — they were typed explicitly.
  const target = parsed.data.target;
  if (target.auth?.profileId && target.value) {
    try {
      const profileHeaders = await profileToHeaders(target.auth.profileId, target.value);
      target.auth = {
        ...target.auth,
        headers: { ...profileHeaders, ...(target.auth.headers ?? {}) },
      };
    } catch (e) {
      return NextResponse.json(
        { error: `failed to load login profile: ${e instanceof Error ? e.message : e}` },
        { status: 400 },
      );
    }
  }

  const scan = makeScan({
    id: randomUUID(),
    kind: parsed.data.kind,
    target,
    selection: parsed.data.selection,
    meta: parsed.data.meta,
  });
  await createScan(scan);

  // Fire-and-forget the runner — UI will follow via SSE.
  void runScan(scan.id).catch((e) => {
    // Persistence is handled inside runScan; here we only log.
    console.error(`[runScan ${scan.id}]`, e);
  });

  return NextResponse.json({ id: scan.id }, { status: 201 });
}

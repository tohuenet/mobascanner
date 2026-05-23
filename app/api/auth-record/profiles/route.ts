/**
 * /api/auth-record/profiles
 *   GET            → list saved login profiles (id + cookie/origin counts).
 *   DELETE ?id=    → remove a saved profile.
 *
 * Profiles live in the encrypted vault (`loginprofile:<id>`); we only ever
 * surface metadata, never the raw storageState.
 */

import { NextResponse, type NextRequest } from "next/server";
import { deleteProfile, listProfiles } from "@/lib/auth/profile";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    return NextResponse.json({ profiles: await listProfiles() });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}

export async function DELETE(req: NextRequest) {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  if (!id) return NextResponse.json({ error: "?id=… required" }, { status: 400 });
  try {
    await deleteProfile(id);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}

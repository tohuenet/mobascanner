/**
 * POST /api/scans/[id]/triage — run LLM triage over the scan's findings.
 *
 * Returns: { decisions, usage, error? } and rewrites the findings JSONL with
 * the merged triage decisions so the UI reflects them on next reload.
 */

import { NextResponse } from "next/server";
import { promises as fs } from "node:fs";
import path from "node:path";
import { listFindings } from "@/lib/store";
import { mergeTriage, triageFindings } from "@/lib/triage/llm";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(_req: Request, ctx: RouteContext<"/api/scans/[id]/triage">) {
  const { id } = await ctx.params;
  const findings = await listFindings(id);
  if (!findings.length) return NextResponse.json({ decisions: [], usage: undefined });

  const { decisions, usage, error } = await triageFindings(findings);
  if (error) return NextResponse.json({ error, decisions, usage }, { status: 500 });

  const merged = mergeTriage(findings, decisions);
  // Rewrite JSONL atomically.
  const file = path.join(process.cwd(), "data", "scans", id, "findings.jsonl");
  const tmp = file + ".tmp";
  await fs.writeFile(tmp, merged.map((m) => JSON.stringify(m)).join("\n") + "\n", "utf8");
  await fs.rename(tmp, file);

  return NextResponse.json({ decisions, usage });
}

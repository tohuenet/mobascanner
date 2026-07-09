/**
 * POST /api/scans/[id]/agentic — kicks off the AI-driven attack-chain loop.
 *
 * Body: { iterations?: number }   (default 5, max 10)
 *
 * Returns: { iterations, probesAccepted, probesRejected, newFindings, ... }
 */

import { NextResponse, type NextRequest } from "next/server";
import { randomUUID } from "node:crypto";
import { getScan, appendFinding, appendLog } from "@/lib/store";
import { scanBus } from "@/lib/engine/events";
import { runAgenticLoop } from "@/lib/triage/agentic";
import type { Finding, Severity } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest, ctx: RouteContext<"/api/scans/[id]/agentic">) {
  const { id } = await ctx.params;
  const body = await req.json().catch(() => ({}));
  const iterations = Math.min(Math.max(Number(body.iterations) || 5, 1), 10);
  const scan = await getScan(id);
  if (!scan) return NextResponse.json({ error: "not found" }, { status: 404 });

  const controller = new AbortController();
  const result = await runAgenticLoop({
    scanId: id,
    target: scan.target,
    options: {},
    signal: controller.signal,
    emit: async (d) => {
      const finding: Finding = { ...d, id: randomUUID(), scanId: id, scannerId: "agentic", scannerName: "AI Attack-Chain", createdAt: Date.now() };
      await appendFinding(id, finding);
      scan.counts[finding.severity as Severity] = (scan.counts[finding.severity as Severity] ?? 0) + 1;
      scanBus.emitEvent({ kind: "finding", scanId: id, finding });
    },
    log: async (level, message) => {
      await appendLog(id, level, message);
      scanBus.emitEvent({ kind: "log", scanId: id, level, message, at: Date.now() });
    },
    progress: async () => { /* not streamed */ },
    // Agentic loop doesn't participate in dynamic discovery — no-op consumer.
    discover: () => false,
  }, { iterations });

  return NextResponse.json(result);
}

/**
 * /api/scans/[id]/stream — Server-Sent Events of scan progress.
 *
 * Replays the current scan state once on connect (so refreshing mid-scan
 * doesn't lose context), then forwards every bus event for that scanId until
 * the scan completes or the client disconnects.
 */

import { scanBus } from "@/lib/engine/events";
import { getScan, listFindings } from "@/lib/store";
import "@/lib/scanners";
import type { ScanEvent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function formatSse(event: ScanEvent): string {
  return `event: ${event.kind}\ndata: ${JSON.stringify(event)}\n\n`;
}

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/stream">) {
  const { id } = await ctx.params;
  const scan = await getScan(id);
  if (!scan) return new Response("not found", { status: 404 });

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const enc = new TextEncoder();
      const send = (e: ScanEvent) => {
        try { controller.enqueue(enc.encode(formatSse(e))); } catch { /* closed */ }
      };

      // 1. Snapshot current state.
      const at = scan.startedAt ?? scan.createdAt;
      send({ kind: "scan-started", scanId: id, at });

      const findings = await listFindings(id);
      for (const f of findings) send({ kind: "finding", scanId: id, finding: f });

      for (const [scannerId, p] of Object.entries(scan.progress)) {
        if (p.state === "running" || p.state === "pending") continue;
        if (p.state === "completed") {
          send({ kind: "scanner-finished", scanId: id, scannerId, findings: p.findingCount ?? 0, at: p.finishedAt ?? Date.now() });
        } else if (p.state === "failed") {
          send({ kind: "scanner-failed", scanId: id, scannerId, error: p.errorMessage ?? "failed", at: p.finishedAt ?? Date.now() });
        }
      }

      // 2. Forward live events.
      const unsub = scanBus.subscribe(id, (e) => send(e));

      const finishOn = (e: ScanEvent) => {
        if (e.kind === "scan-finished" || e.kind === "scan-failed") {
          // Slight delay so the last finding has time to be flushed.
          setTimeout(() => { unsub(); try { controller.close(); } catch {} }, 250);
        }
      };
      const wrapUnsub = scanBus.subscribe(id, finishOn);

      // 3. Heartbeat to keep proxies alive.
      const hb = setInterval(() => { try { controller.enqueue(enc.encode(": ping\n\n")); } catch {} }, 15000);

      // 4. Cleanup on cancel.
      const onCancel = () => {
        clearInterval(hb);
        unsub(); wrapUnsub();
        try { controller.close(); } catch {}
      };

      // We rely on the request being aborted by the client; ReadableStream
      // calls `cancel()` on abort.
      // @ts-expect-error: attach cleanup hook
      controller._mobaCleanup = onCancel;
    },
    cancel() {
      // @ts-expect-error: read cleanup hook
      this._mobaCleanup?.();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}

/**
 * Scan orchestrator.
 *
 * Responsibilities:
 *   1. Load scan from store, mark running.
 *   2. Iterate selected scanners (sequentially for now to avoid resource
 *      contention; parallelism can be opt-in later via `concurrency` option).
 *   3. Stream findings + progress to the bus and JSONL store.
 *   4. Mark scan completed/failed and persist final counts.
 *
 * Cancellation: a per-scan AbortController is registered globally so the
 * /api/scans/[id]/cancel endpoint (or HMR shutdown) can interrupt long runs.
 */

import { randomUUID } from "node:crypto";
import { listScanners, getScanner } from "./registry";
import { scanBus } from "./events";
import {
  appendFinding,
  appendLog,
  freshCounts,
  getScan,
  listFindings,
  updateScan,
} from "../store";
import { detectChains } from "../triage/chains";
import { dedupFindings } from "./dedup";
import { startWebhookListener } from "../notifications/webhooks";
import { startScannerCost, endScannerCost } from "./cost-tracker";
import { startTrafficCapture, endTrafficCapture } from "../web/traffic-capture";
import { startTemplateUpdater } from "../schedule/template-updater";
import { createDiscoveryBus, type DiscoveredItem } from "./discovery";
import type { ScanContext, Scanner } from "./scanner";

// Subscribe webhook listener + template updater on first import.
startWebhookListener();
startTemplateUpdater();
import { promises as fs } from "node:fs";
import path from "node:path";
import type { Finding, Scan, Severity } from "../types";

const activeRuns = new Map<string, AbortController>();

export function cancelScan(scanId: string): boolean {
  const ctl = activeRuns.get(scanId);
  if (!ctl) return false;
  ctl.abort();
  return true;
}

export async function runScan(scanId: string): Promise<void> {
  const scan = await getScan(scanId);
  if (!scan) throw new Error(`Scan ${scanId} not found`);
  if (scan.status === "running") return; // already running

  const controller = new AbortController();
  activeRuns.set(scanId, controller);

  scan.status = "running";
  scan.startedAt = Date.now();
  await updateScan(scan);
  startTrafficCapture(scanId);
  scanBus.emitEvent({ kind: "scan-started", scanId, at: Date.now() });

  const enabled = scan.selection.enabled
    .map((id) => getScanner(id))
    .filter((s): s is NonNullable<ReturnType<typeof getScanner>> => Boolean(s))
    .filter((s) => s.kind === scan.kind);

  if (enabled.length === 0) {
    // Fall back to all-of-kind if user didn't pick anything.
    const fallback = listScanners().filter((s) => s.kind === scan.kind && s.defaultEnabled !== false);
    enabled.push(...fallback);
  }

  // Build a dependency graph and execute scanners in topologically-sorted
  // waves, with all scanners in a wave running concurrently (bounded). This
  // is one of the biggest wins on large targets — sequential 12× scanners
  // that each block on the network turn into ~3 waves of parallel I/O.
  const SAME_KIND_SITEMAP_DEP = "web.crawler"; // every web scanner reads SiteMap.
  const ids = new Set(enabled.map((s) => s.id));
  const waves = topoWaves(enabled.map((s) => ({
    id: s.id,
    deps: (s.dependsOn ?? (s.kind === "web" && s.id !== SAME_KIND_SITEMAP_DEP && ids.has(SAME_KIND_SITEMAP_DEP) ? [SAME_KIND_SITEMAP_DEP] : []))
      .filter((d) => ids.has(d)),
  })));
  const byId = new Map(enabled.map((s) => [s.id, s]));
  const concurrencyCap = Math.min(Math.max(Number(scan.meta?.concurrency) || 6, 1), 12);

  // Per-scan DiscoveryBus: scanners publish URL/form/endpoint findings into
  // it via ctx.discover; consumers (scanners with `consume`) subscribe after
  // the static waves complete. Foundation only in P1 — no built-in scanner
  // calls it yet, so this is silent unless a future scanner opts in.
  const bus = createDiscoveryBus({
    classSampleSize: Number(scan.meta?.discoveryClassSampleSize) || 2,
    maxItems: Number(scan.meta?.discoveryMaxItems) || 5000,
  });

  /** Build the ScanContext given to a scanner. Used both by the wave-phase
   *  scanner.run() and by the consumer-phase scanner.consume() loop. */
  const buildCtx = (scanner: Scanner, addFinding: () => void): ScanContext => ({
    scanId,
    target: scan.target,
    options: scan.selection.options?.[scanner.id] ?? {},
    signal: controller.signal,
    emit: async (d) => {
      const finding: Finding = {
        ...d,
        id: randomUUID(),
        scanId,
        scannerId: scanner.id,
        scannerName: scanner.name,
        createdAt: Date.now(),
      };
      addFinding();
      await appendFinding(scanId, finding);
      scan.counts[finding.severity as Severity] += 1;
      scanBus.emitEvent({ kind: "finding", scanId, finding });
    },
    log: async (level, message) => {
      await appendLog(scanId, level, `[${scanner.id}] ${message}`);
      scanBus.emitEvent({ kind: "log", scanId, level, message: `[${scanner.id}] ${message}`, at: Date.now() });
    },
    progress: async (fraction, message) => {
      const cur = scan.progress[scanner.id];
      if (cur) cur.progress = Math.max(0, Math.min(1, fraction));
      scanBus.emitEvent({ kind: "scanner-progress", scanId, scannerId: scanner.id, progress: fraction, message });
    },
    discover: (item: DiscoveredItem) => {
      const isNew = bus.publish(item);
      if (isNew) {
        scanBus.emitEvent({
          kind: "discovered",
          scanId,
          item: {
            kind: item.kind,
            url: item.kind === "form" ? item.form.action : item.url,
            method: item.kind === "form" ? item.form.method : item.kind === "endpoint" ? item.method : item.method,
            source: item.source,
          },
          at: Date.now(),
        });
      }
      return isNew;
    },
  });

  const runOneScanner = async (scannerId: string) => {
    if (controller.signal.aborted) return;
    const scanner = byId.get(scannerId)!;
    const startedAt = Date.now();
    scan.progress[scanner.id] = { scannerId: scanner.id, state: "running", startedAt, progress: 0 };
    await updateScan(scan);
    scanBus.emitEvent({ kind: "scanner-started", scanId, scannerId: scanner.id, at: startedAt });
    startScannerCost(scanId, scanner.id);

    let findingCount = 0;
    try {
      await scanner.run(buildCtx(scanner, () => { findingCount += 1; }));
      const finishedAt = Date.now();
      scan.progress[scanner.id] = { ...scan.progress[scanner.id], state: "completed", progress: 1, finishedAt, findingCount };
      scanBus.emitEvent({ kind: "scanner-finished", scanId, scannerId: scanner.id, findings: findingCount, at: finishedAt });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      scan.progress[scanner.id] = { ...scan.progress[scanner.id], state: "failed", finishedAt: Date.now(), errorMessage: message };
      scanBus.emitEvent({ kind: "scanner-failed", scanId, scannerId: scanner.id, error: message, at: Date.now() });
      await appendLog(scanId, "error", `[${scanner.id}] ${message}`);
    }
    endScannerCost();
    await updateScan(scan);
  };

  try {
    for (const wave of waves) {
      if (controller.signal.aborted) break;
      // Split wave into "parallelSafe" (run concurrently with cap) and
      // "serial" (run one at a time, after the parallel batch).
      const parallel = wave.filter((id) => byId.get(id)?.parallelSafe !== false);
      const serial = wave.filter((id) => byId.get(id)?.parallelSafe === false);

      // Bounded concurrency over the parallel set.
      let cursor = 0;
      const workers = Array.from({ length: Math.min(concurrencyCap, parallel.length) }, async () => {
        while (cursor < parallel.length && !controller.signal.aborted) {
          const i = cursor++;
          await runOneScanner(parallel[i]);
        }
      });
      await Promise.all(workers);

      for (const id of serial) {
        if (controller.signal.aborted) break;
        await runOneScanner(id);
      }
    }

    // ── Consumer phase ──────────────────────────────────────────────────
    // Any scanner that declared `consume` gets subscribed to the bus AFTER
    // its (and everyone's) static wave finishes. We replay the bus snapshot
    // through each consumer first so they see items that were published
    // before they hooked up, then wait for the bus to drain.
    const consumers = enabled.filter((s): s is Scanner & { consume: NonNullable<Scanner["consume"]> } => typeof s.consume === "function");
    if (consumers.length > 0 && !controller.signal.aborted) {
      const unsubs: Array<() => void> = [];
      try {
        for (const scanner of consumers) {
          const ctx = buildCtx(scanner, () => { /* per-consume finding count not tracked */ });
          const accepts = (item: DiscoveredItem): boolean => {
            if (item.source.scannerId === scanner.id) return false; // ignore own emits
            if (scanner.consumes && !scanner.consumes.includes(item.kind)) return false;
            return true;
          };
          const handle = async (item: DiscoveredItem) => {
            if (!accepts(item)) return;
            try {
              await scanner.consume(item, ctx);
            } catch (e) {
              await appendLog(scanId, "warn", `[${scanner.id}] consume: ${e instanceof Error ? e.message : e}`);
            }
          };
          // Subscribe FIRST so we don't miss any item published during replay.
          unsubs.push(bus.subscribe(handle));
          // Replay current snapshot.
          const snap = bus.snapshot();
          for (const u of snap.urls) await handle(u);
          for (const e of snap.endpoints) await handle(e);
          for (const f of snap.forms) await handle({ kind: "form", form: f, source: { scannerId: "(replay)", via: "snapshot" } });
        }

        const budgetMs = Math.min(
          Math.max(Number(scan.meta?.discoveryBudgetMs) || 5 * 60_000, 10_000),
          30 * 60_000,
        );
        const { timedOut } = await bus.drained({ budgetMs });
        const stats = bus.snapshot();
        await appendLog(
          scanId,
          timedOut ? "warn" : "info",
          `[discovery] ${stats.urls.length} URLs / ${stats.forms.length} forms / ${stats.endpoints.length} endpoints across ${stats.classCount} page-class(es)${stats.clusterDropped ? `, ${stats.clusterDropped} clustered` : ""}${stats.overflowDropped ? `, ${stats.overflowDropped} overflow-dropped` : ""}${timedOut ? " — drain timed out" : ""}`,
        );
      } finally {
        for (const u of unsubs) u();
      }
    }

    // Chain detection — run after all scanners, before marking the scan
    // complete, so composite findings are streamed to the UI like any other.
    if (!controller.signal.aborted) {
      try {
        const all = await listFindings(scanId);
        const chains = detectChains(scanId, all);
        for (const c of chains) {
          await appendFinding(scanId, c);
          scan.counts[c.severity as Severity] += 1;
          scanBus.emitEvent({ kind: "finding", scanId, finding: c });
        }
        if (chains.length) await appendLog(scanId, "info", `[chain] detected ${chains.length} composite finding(s)`);
      } catch (e) {
        await appendLog(scanId, "warn", `[chain] ${e instanceof Error ? e.message : e}`);
      }
    }

    // Dedup post-process — collapse findings that multiple scanners caught
    // for the same root cause + location into a single finding with merged
    // evidence. Recomputes severity counts from the deduped set.
    if (!controller.signal.aborted) {
      try {
        const all = await listFindings(scanId);
        const { kept, collapsedCount } = dedupFindings(all);
        if (collapsedCount > 0) {
          const file = path.join(process.cwd(), "data", "scans", scanId, "findings.jsonl");
          const tmp = file + ".tmp";
          await fs.writeFile(tmp, kept.map((k) => JSON.stringify(k)).join("\n") + (kept.length ? "\n" : ""), "utf8");
          await fs.rename(tmp, file);
          // Recompute severity counts.
          const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
          for (const f of kept) counts[f.severity as Severity] += 1;
          scan.counts = counts;
          await appendLog(scanId, "info", `[dedup] collapsed ${collapsedCount} duplicate(s); ${kept.length} unique findings remain`);
          scanBus.emitEvent({ kind: "log", scanId, level: "info", message: `[dedup] collapsed ${collapsedCount}`, at: Date.now() });
        }
      } catch (e) {
        await appendLog(scanId, "warn", `[dedup] ${e instanceof Error ? e.message : e}`);
      }
    }

    scan.status = controller.signal.aborted ? "cancelled" : "completed";
    scan.finishedAt = Date.now();
    await updateScan(scan);
    scanBus.emitEvent({ kind: "scan-finished", scanId, at: scan.finishedAt, counts: scan.counts });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    scan.status = "failed";
    scan.errorMessage = message;
    scan.finishedAt = Date.now();
    await updateScan(scan);
    scanBus.emitEvent({ kind: "scan-failed", scanId, error: message, at: Date.now() });
  } finally {
    endTrafficCapture();
    activeRuns.delete(scanId);
  }
}

/**
 * Topological wave sort: returns an array of "waves", each containing scanner
 * ids that can all run concurrently because none depend on another in the
 * same wave. Cycles fall through (deps in unknown order).
 */
function topoWaves(nodes: { id: string; deps: string[] }[]): string[][] {
  const remaining = new Map(nodes.map((n) => [n.id, new Set(n.deps)]));
  const waves: string[][] = [];
  while (remaining.size) {
    const ready: string[] = [];
    for (const [id, deps] of remaining) if (deps.size === 0) ready.push(id);
    if (!ready.length) {
      // Cycle / unresolvable — put everything left into one final wave.
      waves.push([...remaining.keys()]);
      break;
    }
    waves.push(ready);
    for (const id of ready) remaining.delete(id);
    for (const deps of remaining.values()) for (const id of ready) deps.delete(id);
  }
  return waves;
}

/** Used by the API endpoint when creating a fresh scan. */
export function makeScan(args: Pick<Scan, "id" | "kind" | "target" | "selection" | "meta">): Scan {
  return {
    id: args.id,
    kind: args.kind,
    target: args.target,
    selection: args.selection,
    status: "queued",
    createdAt: Date.now(),
    progress: Object.fromEntries(
      args.selection.enabled.map((id) => [id, { scannerId: id, state: "pending" as const }]),
    ),
    counts: freshCounts(),
    meta: args.meta,
  };
}

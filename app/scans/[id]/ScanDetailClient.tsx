"use client";

/**
 * Scan-detail orchestrator.
 *
 * Owns the long-lived state for one scan run: reducer over SSE events from
 * /api/scans/[id]/stream, accumulated findings, log lines, and a 1s tick used
 * by the header to surface elapsed time. Renders results-first:
 *
 *   ScanHeader        — what was scanned + status + overflow menu
 *   SeverityCounters  — the answer (5 big numbers)
 *   Tabs              — Findings / Site map / Activity / Logs
 *
 * Process detail (per-scanner progress, log stream) moved into the Activity
 * and Logs tabs so they're discoverable but never compete with results for
 * attention.
 */

import { Suspense, useEffect, useReducer, useState } from "react";
import { ScanHeader } from "@/components/ScanHeader";
import { SeverityCounters } from "@/components/SeverityCounters";
import { Tabs, type TabItem } from "@/components/scan-tabs/Tabs";
import { FindingsTab } from "@/components/scan-tabs/FindingsTab";
import { ActivityTab } from "@/components/scan-tabs/ActivityTab";
import { LogsTab } from "@/components/scan-tabs/LogsTab";
import { SiteMapTab } from "@/components/scan-tabs/SiteMapTab";
import type { Finding, Scan, ScanEvent, ScanProgress, Severity } from "@/lib/types";

export interface DiscoveredEvent {
  kind: "url" | "form" | "endpoint";
  url?: string;
  method?: string;
  source: { scannerId: string; via: string; parentUrl?: string };
  at: number;
}

interface State {
  scan: Scan;
  findings: Finding[];
  logs: { at: number; level: string; message: string }[];
  /** Live items emitted via SSE "discovered" — capped to 200 most recent. */
  discovered: DiscoveredEvent[];
}

type Action = { type: "event"; event: ScanEvent };

function reducer(state: State, action: Action): State {
  if (action.type !== "event") return state;
  const e = action.event;
  switch (e.kind) {
    case "scan-started":
      return { ...state, scan: { ...state.scan, status: "running", startedAt: e.at } };
    case "scanner-started":
      return {
        ...state,
        scan: {
          ...state.scan,
          progress: {
            ...state.scan.progress,
            [e.scannerId]: {
              scannerId: e.scannerId,
              state: "running",
              startedAt: e.at,
              progress: 0,
            },
          },
        },
      };
    case "scanner-progress": {
      const cur =
        state.scan.progress[e.scannerId] ??
        { scannerId: e.scannerId, state: "running" as const };
      return {
        ...state,
        scan: {
          ...state.scan,
          progress: {
            ...state.scan.progress,
            [e.scannerId]: { ...cur, progress: e.progress },
          },
        },
      };
    }
    case "scanner-finished": {
      const cur =
        state.scan.progress[e.scannerId] ??
        { scannerId: e.scannerId, state: "running" as const };
      return {
        ...state,
        scan: {
          ...state.scan,
          progress: {
            ...state.scan.progress,
            [e.scannerId]: {
              ...cur,
              state: "completed",
              finishedAt: e.at,
              progress: 1,
              findingCount: e.findings,
            },
          },
        },
      };
    }
    case "scanner-failed": {
      const cur =
        state.scan.progress[e.scannerId] ??
        { scannerId: e.scannerId, state: "running" as const };
      return {
        ...state,
        scan: {
          ...state.scan,
          progress: {
            ...state.scan.progress,
            [e.scannerId]: {
              ...cur,
              state: "failed",
              finishedAt: e.at,
              errorMessage: e.error,
            },
          },
        },
      };
    }
    case "finding": {
      // SSE can reconnect mid-flight; de-dupe by id.
      if (state.findings.some((f) => f.id === e.finding.id)) return state;
      const counts = { ...state.scan.counts };
      counts[e.finding.severity as Severity] =
        (counts[e.finding.severity as Severity] ?? 0) + 1;
      return {
        ...state,
        findings: [e.finding, ...state.findings],
        scan: { ...state.scan, counts },
      };
    }
    case "scan-finished":
      return {
        ...state,
        scan: { ...state.scan, status: "completed", finishedAt: e.at, counts: e.counts },
      };
    case "scan-failed":
      return {
        ...state,
        scan: {
          ...state.scan,
          status: "failed",
          errorMessage: e.error,
          finishedAt: e.at,
        },
      };
    case "log":
      return {
        ...state,
        // Cap to last 500 lines so the reducer state stays bounded.
        logs: [...state.logs.slice(-500), { at: e.at, level: e.level, message: e.message }],
      };
    case "discovered":
      return {
        ...state,
        // Cap to last 200 — the static SiteMap covers the long tail. The bus
        // dedupes upstream so we shouldn't see runaway duplicates here either.
        discovered: [
          ...state.discovered.slice(-199),
          { ...e.item, at: e.at },
        ],
      };
    default:
      return state;
  }
}

export function ScanDetailClient({
  initialScan,
  initialFindings,
}: {
  initialScan: Scan;
  initialFindings: Finding[];
}) {
  const [state, dispatch] = useReducer(reducer, {
    scan: {
      ...initialScan,
      counts: {
        ...{ critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        ...initialScan.counts,
      },
    },
    findings: initialFindings,
    logs: [],
    discovered: [],
  });

  const isRunning = state.scan.status === "running" || state.scan.status === "queued";

  // SSE subscription — only while the scan can still produce events.
  useEffect(() => {
    if (
      state.scan.status === "completed" ||
      state.scan.status === "failed" ||
      state.scan.status === "cancelled"
    ) {
      return;
    }
    const es = new EventSource(`/api/scans/${state.scan.id}/stream`);
    const handler = (ev: MessageEvent) => {
      try {
        const data = JSON.parse(ev.data) as ScanEvent;
        dispatch({ type: "event", event: data });
      } catch {
        /* ignore malformed payload */
      }
    };
    for (const k of [
      "scan-started",
      "scanner-started",
      "scanner-progress",
      "scanner-finished",
      "scanner-failed",
      "finding",
      "scan-finished",
      "scan-failed",
      "log",
      "discovered",
    ] as const) {
      es.addEventListener(k, handler);
    }
    es.onerror = () => {
      /* Browser retries automatically. We close from cleanup on terminal status. */
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.scan.id]);

  // 1s tick so the header's elapsed-time updates while running. Stops on
  // terminal status to avoid useless re-renders.
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    if (!isRunning) return;
    const t = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(t);
  }, [isRunning]);

  const progressEntries = Object.values(state.scan.progress) as ScanProgress[];
  const overallProgress =
    progressEntries.length === 0
      ? 0
      : progressEntries.reduce(
          (a, p) => a + (p.progress ?? (p.state === "completed" ? 1 : 0)),
          0,
        ) / progressEntries.length;

  const totalFindings = (Object.values(state.scan.counts) as number[]).reduce(
    (a, b) => a + b,
    0,
  );

  const runningScanners = progressEntries.filter((p) => p.state === "running").length;
  const failedScanners = progressEntries.filter((p) => p.state === "failed").length;

  const tabs: TabItem[] = [
    { id: "findings", label: "Findings", badge: totalFindings || undefined },
    {
      id: "sitemap",
      label: "Site map",
      // Live counter ticks up as the crawler / SPA crawler publish items.
      badge: state.discovered.length || undefined,
    },
    {
      id: "activity",
      label: "Activity",
      badge:
        isRunning && runningScanners > 0
          ? runningScanners
          : failedScanners || undefined,
    },
    { id: "logs", label: "Logs", badge: state.logs.length || undefined },
  ];

  return (
    <div className="grid gap-6">
      <ScanHeader scan={state.scan} totalFindings={totalFindings} nowMs={nowMs} />

      <SeverityCounters
        counts={state.scan.counts}
        overallProgress={overallProgress}
        running={isRunning}
      />

      {state.scan.errorMessage && (
        <div
          role="alert"
          className="glass p-3 md-body-m"
          style={{
            borderColor: "color-mix(in oklab, var(--md-error) 45%, transparent)",
            color: "var(--md-error)",
          }}
        >
          {state.scan.errorMessage}
        </div>
      )}

      <Suspense fallback={null}>
        <Tabs tabs={tabs} defaultId="findings" ariaLabel="Scan sections">
          {(activeId) => {
            switch (activeId) {
              case "findings":
                return <FindingsTab findings={state.findings} />;
              case "sitemap":
                return (
                  <SiteMapTab
                    scanId={state.scan.id}
                    discovered={state.discovered}
                  />
                );
              case "activity":
                return <ActivityTab progress={state.scan.progress} />;
              case "logs":
                return <LogsTab logs={state.logs} />;
              default:
                return null;
            }
          }}
        </Tabs>
      </Suspense>
    </div>
  );
}

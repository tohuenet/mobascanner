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

import Link from "next/link";
import { Suspense, useEffect, useReducer, useState } from "react";
import { ScanHeader } from "@/components/ScanHeader";
import { SeverityCounters } from "@/components/SeverityCounters";
import { Tabs, type TabItem } from "@/components/scan-tabs/Tabs";
import { SummaryTab } from "@/components/scan-tabs/SummaryTab";
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

/** A project this scan belongs to, with its correlated-finding count. */
export interface ScanProjectPointer {
  id: string;
  name: string;
  correlatedCount: number;
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
  projects = [],
}: {
  initialScan: Scan;
  initialFindings: Finding[];
  /** Projects this scan is a member of — drives the cross-surface banner. */
  projects?: ScanProjectPointer[];
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
    { id: "summary", label: "Summary" },
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

      <StatusNotice scan={state.scan} />

      <ProjectBanner projects={projects} />

      <Suspense fallback={null}>
        <Tabs tabs={tabs} defaultId="summary" ariaLabel="Scan sections">
          {(activeId) => {
            switch (activeId) {
              case "summary":
                return <SummaryTab scan={state.scan} findings={state.findings} />;
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

/**
 * Cross-surface banner — shown only when this scan is a member of one or more
 * projects. Points to the correlated project report where DAST×SAST/SCA findings
 * are joined. Absent entirely otherwise. Each row is a single link so its full
 * text ("Part of project … · N cross-surface findings · View project") is the
 * accessible name.
 */
function ProjectBanner({ projects }: { projects: ScanProjectPointer[] }) {
  if (projects.length === 0) return null;
  return (
    <div className="flex flex-col gap-2 print:hidden" aria-label="Cross-surface projects">
      {projects.map((p) => (
        <Link
          key={p.id}
          href={`/projects/${p.id}`}
          className="glass p-4 state-layer hover:translate-y-[-1px] transition-transform flex flex-wrap items-center gap-x-3 gap-y-1"
          style={{ borderColor: "color-mix(in oklab, var(--md-tertiary) 45%, transparent)" }}
        >
          <span
            className="inline-flex items-center gap-1.5 px-2.5 h-6 rounded-full md-label-s uppercase tracking-wide shrink-0"
            style={{
              color: "var(--md-tertiary)",
              background: "color-mix(in oklab, var(--md-tertiary) 16%, transparent)",
              border: "1px solid color-mix(in oklab, var(--md-tertiary) 40%, transparent)",
            }}
          >
            cross-surface
          </span>
          <span className="md-body-m min-w-0">
            Part of project <span className="md-title-s break-words">{p.name}</span>
            <span aria-hidden> · </span>
            {p.correlatedCount > 0
              ? `${p.correlatedCount} cross-surface finding${p.correlatedCount === 1 ? "" : "s"}`
              : "not yet correlated"}
          </span>
          <span className="md-label-l text-[color:var(--md-primary)] ml-auto shrink-0">
            View project →
          </span>
        </Link>
      ))}
    </div>
  );
}

/**
 * Explicit report states for terminal-but-not-clean scans. A `failed` scan
 * surfaces its error and a way to run again; a `cancelled` scan reassures the
 * reader that whatever was collected before the stop is retained below.
 */
function StatusNotice({ scan }: { scan: Scan }) {
  if (scan.status === "failed") {
    return (
      <div
        role="alert"
        className="glass p-4 flex flex-col gap-3"
        style={{ borderColor: "color-mix(in oklab, var(--md-error) 45%, transparent)" }}
      >
        <div className="flex flex-col gap-1">
          <span className="md-title-s" style={{ color: "var(--md-error)" }}>
            Scan failed
          </span>
          <p className="md-body-m text-[color:var(--md-on-surface-variant)] whitespace-pre-wrap break-words">
            {scan.errorMessage ?? "The scan stopped before completing. Any findings collected before the failure are shown below."}
          </p>
        </div>
        <Link
          href={scan.kind === "web" ? "/scan/web" : "/scan/source"}
          className="state-layer inline-flex items-center gap-2 h-9 px-4 rounded-full w-fit bg-[color:var(--md-primary)] text-[color:var(--md-on-primary)] md-label-l shadow-sm"
        >
          Retry — start a new scan
        </Link>
      </div>
    );
  }

  if (scan.status === "cancelled") {
    return (
      <div
        className="glass p-4 flex flex-col gap-1"
        style={{ borderColor: "color-mix(in oklab, var(--md-tertiary) 45%, transparent)" }}
      >
        <span className="md-title-s" style={{ color: "var(--md-tertiary)" }}>
          Scan cancelled
        </span>
        <p className="md-body-m text-[color:var(--md-on-surface-variant)]">
          This scan was stopped early. Partial results collected before cancellation are retained and shown below.
        </p>
      </div>
    );
  }

  if (scan.errorMessage) {
    return (
      <div
        role="alert"
        className="glass p-3 md-body-m"
        style={{
          borderColor: "color-mix(in oklab, var(--md-error) 45%, transparent)",
          color: "var(--md-error)",
        }}
      >
        {scan.errorMessage}
      </div>
    );
  }

  return null;
}

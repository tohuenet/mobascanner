"use client";

/**
 * ActivityTab — per-scanner progress list. This used to live inline in the
 * scan-detail header alongside the severity counters; moving it here keeps the
 * main page focused on results while still making process visibility a single
 * click away.
 *
 * Scanners are sorted so running ones float to the top, then queued/pending,
 * then completed (most-recently-finished first), then failed.
 */

import { Chip, ProgressBar } from "../ui/Primitives";
import type { ScanProgress } from "@/lib/types";

const STATE_ORDER: Record<ScanProgress["state"], number> = {
  running: 0,
  pending: 1,
  completed: 2,
  failed: 3,
  skipped: 4,
};

function compareProgress(a: ScanProgress, b: ScanProgress): number {
  const sa = STATE_ORDER[a.state] ?? 99;
  const sb = STATE_ORDER[b.state] ?? 99;
  if (sa !== sb) return sa - sb;
  // Within the same state, completed scanners sort most-recent first.
  if (a.state === "completed" || a.state === "failed") {
    return (b.finishedAt ?? 0) - (a.finishedAt ?? 0);
  }
  return a.scannerId.localeCompare(b.scannerId);
}

export function ActivityTab({
  progress,
}: {
  progress: Record<string, ScanProgress>;
}) {
  const entries = (Object.values(progress) as ScanProgress[]).slice().sort(compareProgress);

  if (entries.length === 0) {
    return (
      <div className="glass-thin p-10 text-center text-[color:var(--md-on-surface-variant)]">
        No scanner activity yet.
      </div>
    );
  }

  return (
    <div className="grid gap-2">
      {entries.map((p) => {
        const running = p.state === "running";
        const failed = p.state === "failed";
        const completed = p.state === "completed";
        return (
          <div key={p.scannerId} className="glass-thin p-3 flex items-center gap-3">
            <Chip
              className="!h-6 !px-2"
              selected={completed}
              style={
                failed
                  ? { color: "var(--md-error)", borderColor: "var(--md-error)" }
                  : undefined
              }
            >
              {p.state}
            </Chip>
            <span className="md-label-l mono flex-1 break-all min-w-0">{p.scannerId}</span>
            <div className="w-40 hidden sm:block">
              <ProgressBar
                value={p.progress ?? (completed ? 1 : 0)}
                indeterminate={running && (p.progress ?? 0) === 0}
              />
            </div>
            {p.findingCount !== undefined && (
              <span className="md-body-s text-[color:var(--md-on-surface-variant)] w-16 text-right">
                {p.findingCount} found
              </span>
            )}
            {p.errorMessage && (
              <span
                className="md-body-s w-full sm:w-auto text-[color:var(--md-error)] break-words"
                title={p.errorMessage}
              >
                {p.errorMessage.length > 80 ? p.errorMessage.slice(0, 80) + "…" : p.errorMessage}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

"use client";

/**
 * SeverityCounters — five big number tiles, one per severity. The primary
 * "what's the result" visual on the scan-detail page. A thin progress bar at
 * the bottom only appears while the scan is running.
 */

import { ProgressBar } from "./ui/Primitives";
import type { Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityCounters({
  counts,
  overallProgress,
  running,
}: {
  counts: Record<Severity, number>;
  overallProgress: number;
  running: boolean;
}) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {SEVERITIES.map((s) => {
          const color = `var(--md-severity-${s})`;
          const value = counts[s] ?? 0;
          return (
            <div
              key={s}
              className="glass-thin flex flex-col items-center justify-center py-5 px-3 rounded-2xl"
              style={{
                borderColor: `color-mix(in oklab, ${color} 35%, transparent)`,
                background: `color-mix(in oklab, ${color} 6%, transparent)`,
              }}
            >
              <span
                className="leading-none"
                style={{
                  color,
                  fontSize: "clamp(2rem, 4vw, 2.75rem)",
                  fontWeight: 500,
                  fontVariantNumeric: "tabular-nums",
                }}
              >
                {value}
              </span>
              <span className="md-label-l uppercase tracking-wider text-[color:var(--md-on-surface-variant)] mt-2">
                {s}
              </span>
            </div>
          );
        })}
      </div>
      {running && (
        <ProgressBar
          value={overallProgress}
          indeterminate={overallProgress === 0}
        />
      )}
    </div>
  );
}

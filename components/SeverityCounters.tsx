"use client";

/**
 * SeverityCounters — the primary "what's the result" visual on the scan-detail
 * page: one big-number tile per severity plus a Total tile.
 *
 * Each tile is a real, keyboard-operable button that deep-links to the Findings
 * tab pre-filtered to that severity. Navigation is driven purely through URL
 * state (`?tab=findings&sev=<severity>`) so the counters, the filter chips in
 * FindingsList, and any shared link all stay in sync. We use `useRouter` only
 * (no `useSearchParams`) so the tiles need no Suspense boundary; the deep-link
 * fully specifies `tab` + `sev`, and there are no other params to preserve.
 *
 * A thin progress bar at the bottom only appears while the scan is running.
 */

import { useRouter } from "next/navigation";
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
  const router = useRouter();
  const total = SEVERITIES.reduce((a, s) => a + (counts[s] ?? 0), 0);

  // Deep-link to Findings filtered to a severity (or "all" for the Total tile).
  // Replace (not push) to mirror the Tabs URL-sync and avoid history bloat.
  function goto(sev: Severity | "all") {
    router.replace(`?tab=findings&sev=${sev}`, { scroll: false });
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {SEVERITIES.map((s) => (
          <CounterTile
            key={s}
            value={counts[s] ?? 0}
            label={s}
            color={`var(--md-severity-${s})`}
            onSelect={() => goto(s)}
          />
        ))}
        <CounterTile
          value={total}
          label="total"
          color="var(--md-primary)"
          onSelect={() => goto("all")}
        />
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

function CounterTile({
  value,
  label,
  color,
  onSelect,
}: {
  value: number;
  label: string;
  color: string;
  onSelect: () => void;
}) {
  const noun = value === 1 ? "finding" : "findings";
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-label={
        label === "total"
          ? `Total ${value} ${noun}. Show all findings.`
          : `${label} severity: ${value} ${noun}. Filter findings to ${label}.`
      }
      className="glass-thin state-layer flex flex-col items-center justify-center py-5 px-3 rounded-2xl text-center transition-transform hover:-translate-y-0.5"
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
        {label}
      </span>
    </button>
  );
}

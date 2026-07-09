"use client";

/**
 * Dashboard scanner inventory (T1.4).
 *
 * The scanner *names/descriptions* are server-rendered from the registry
 * (cheap metadata — no process spawns), so the list is present on first paint
 * and works without JS. Live availability is layered in on the client by
 * fetching `/api/tools` (the same endpoint ScannerSelector + ToolsManager use),
 * because per-scanner detection spawns a CLI `--version` probe and is far too
 * heavy to run inline on every dashboard render.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { ToolStatusBadge } from "@/components/ui/Primitives";
import type { ScanKind, ToolStatus } from "@/lib/types";

export interface ScannerMeta {
  id: string;
  name: string;
  kind: ScanKind;
  description: string;
}

type StatusMap = Record<string, ToolStatus>;

const GROUPS: { kind: ScanKind; label: string }[] = [
  { kind: "web", label: "Web · DAST" },
  { kind: "source", label: "Source · SAST / SCA" },
];

export function ScannerInventory({ scanners }: { scanners: ScannerMeta[] }) {
  const [statuses, setStatuses] = useState<StatusMap | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let abort = false;
    fetch("/api/tools")
      .then((r) => r.json())
      .then((data: { tools?: { id: string; status: ToolStatus }[] }) => {
        if (abort) return;
        const map: StatusMap = {};
        for (const t of data.tools ?? []) map[t.id] = t.status;
        setStatuses(map);
      })
      .catch(() => {
        if (!abort) setError(true);
      });
    return () => {
      abort = true;
    };
  }, []);

  const total = scanners.length;
  const ready = statuses ? scanners.filter((s) => statuses[s.id] === "available").length : 0;

  const summary = error
    ? `${total} scanners`
    : statuses
      ? `${ready}/${total} scanners ready`
      : `Checking ${total} scanners…`;

  return (
    <section className="grid gap-4" aria-labelledby="inventory-heading">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h2 id="inventory-heading" className="md-headline-s">
            Scanner inventory
          </h2>
          <p className="md-body-m text-[color:var(--md-on-surface-variant)] mt-0.5 max-w-2xl">
            Every adapter wraps an upstream open-source project (or runs built-in). Missing CLIs are skipped gracefully.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span
            className="md-label-l text-[color:var(--md-on-surface-variant)] whitespace-nowrap"
            aria-live="polite"
          >
            {summary}
          </span>
          <Link
            href="/tools"
            className="state-layer inline-flex items-center gap-1.5 h-10 px-4 rounded-full border border-[color:var(--md-outline)] md-label-l whitespace-nowrap"
          >
            Manage tools
            <span aria-hidden>→</span>
          </Link>
        </div>
      </div>

      {GROUPS.map((g) => {
        const items = scanners.filter((s) => s.kind === g.kind);
        if (items.length === 0) return null;
        const groupReady = statuses ? items.filter((s) => statuses[s.id] === "available").length : null;
        return (
          <div key={g.kind} className="grid gap-2">
            <div className="flex items-center gap-2">
              <h3 className="md-label-l text-[color:var(--md-on-surface-variant)] uppercase tracking-wide">
                {g.label}
              </h3>
              <span className="md-label-s text-[color:var(--md-on-surface-variant)]">
                {groupReady !== null ? `${groupReady}/${items.length} ready` : `${items.length}`}
              </span>
            </div>
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              {items.map((s) => (
                <div key={s.id} className="glass-thin p-4 flex flex-col gap-2">
                  <div className="flex items-center gap-2">
                    <h4 className="md-title-s flex-1 min-w-0 truncate">{s.name}</h4>
                    <ToolStatusBadge status={statuses?.[s.id]} error={error} className="shrink-0" />
                  </div>
                  <p className="md-body-s text-[color:var(--md-on-surface-variant)] line-clamp-2">
                    {s.description}
                  </p>
                  <div className="md-label-s text-[color:var(--md-on-surface-variant)] mono truncate">{s.id}</div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </section>
  );
}

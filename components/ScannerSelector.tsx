"use client";

import { useEffect, useMemo, useState } from "react";
import { Switch, Chip, SeverityBadge, ToolStatusBadge } from "./ui/Primitives";
import { SetupChecklist } from "./auth/SetupChecklist";
import type { ToolInfo } from "@/lib/types";

export interface ScannerSelectorState {
  enabled: Record<string, boolean>;
}

/** Scanners that need the Chromium binary installed. Drives the inline
 *  setup-hint shown beneath the selector when any of these are enabled. */
const PLAYWRIGHT_SCANNERS = new Set(["web.spa-crawler", "web.dom-xss"]);

export function ScannerSelector({
  kind,
  state,
  onChange,
}: {
  kind: "web" | "source";
  state: ScannerSelectorState;
  onChange: (next: ScannerSelectorState) => void;
}) {
  const [tools, setTools] = useState<(ToolInfo & { defaultEnabled?: boolean })[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // `loading` already initializes to true, so we don't setState synchronously
    // here (this component is mounted per-route, so `kind` never changes without
    // a remount). Avoids the react-hooks cascading-render lint error.
    let abort = false;
    fetch("/api/tools")
      .then((r) => r.json())
      .then((data) => {
        if (abort) return;
        const filtered = (data.tools as (ToolInfo & { defaultEnabled?: boolean })[]).filter((t) => t.kind === kind);
        setTools(filtered);
        // Seed defaults if state is empty
        if (Object.keys(state.enabled).length === 0) {
          const defaults: Record<string, boolean> = {};
          // Default-on for every scanner whose CLI is actually present in the
          // image. The ScannerSelector previously honored a per-scanner
          // `defaultEnabled` flag, but inside the Docker image we want the
          // full sweep wired up by default — the user can opt out per row.
          for (const t of filtered) defaults[t.id] = t.status === "available";
          onChange({ enabled: defaults });
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
    return () => { abort = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind]);

  const anyPlaywrightEnabled = useMemo(
    () => tools.some((t) => PLAYWRIGHT_SCANNERS.has(t.id) && state.enabled[t.id]),
    [tools, state.enabled],
  );

  if (loading) {
    return (
      <div className="grid gap-2">
        {[0, 1, 2].map((i) => (
          <div key={i} className="glass-thin h-20 animate-pulse" />
        ))}
      </div>
    );
  }

  return (
    <div className="grid gap-2">
      {tools.map((t) => {
        const checked = !!state.enabled[t.id];
        const disabled = t.status === "missing" && t.backend !== "builtin";
        return (
          <div
            key={t.id}
            className={`glass-thin p-3.5 flex items-start gap-3 transition-opacity ${disabled ? "opacity-70" : ""}`}
          >
            <div className="pt-0.5">
              <Switch
                checked={checked && !disabled}
                onChange={(next) => onChange({ enabled: { ...state.enabled, [t.id]: next } })}
              />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="md-title-s">{t.name}</span>
                {t.detectedVersion && (
                  <span className="md-label-s text-[color:var(--md-on-surface-variant)] mono">
                    {t.detectedVersion.length > 40 ? t.detectedVersion.slice(0, 40) + "…" : t.detectedVersion}
                  </span>
                )}
                <ToolStatusBadge status={t.status} />
                <Chip className="!h-6 !px-2">{t.backend}</Chip>
                {t.license && (
                  <span className="md-label-s text-[color:var(--md-on-surface-variant)]">{t.license}</span>
                )}
              </div>
              <p className="md-body-s text-[color:var(--md-on-surface-variant)] mt-1">{t.description}</p>
              {t.status === "missing" && t.installHint && (
                <p className="md-body-s mt-1.5 text-[color:var(--md-on-surface-variant)]">
                  Install: <span className="mono text-[color:var(--md-on-surface)]">{t.installHint}</span>
                </p>
              )}
              {t.upstream && (
                <a
                  href={t.upstream}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="md-label-s text-[color:var(--md-primary)] hover:underline mt-1 inline-block"
                >
                  upstream ↗
                </a>
              )}
            </div>
          </div>
        );
      })}
      {/* Inline setup hint: one of the enabled scanners needs Chromium. The
          SetupChecklist auto-collapses to a compact ✓ when everything's ready,
          and shows a 1-click Install Chromium button when it isn't. */}
      {anyPlaywrightEnabled && (
        <div className="mt-2 grid gap-2">
          <span className="md-label-s text-[color:var(--md-on-surface-variant)]">
            One of your selected scanners runs in a real browser.
          </span>
          <SetupChecklist />
        </div>
      )}

      {/* Severity legend */}
      <div className="glass-thin p-3 flex flex-wrap gap-2 mt-1">
        <span className="md-label-s text-[color:var(--md-on-surface-variant)] mr-1">severity legend:</span>
        {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
          <SeverityBadge key={s} severity={s} />
        ))}
      </div>
    </div>
  );
}

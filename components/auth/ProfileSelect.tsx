"use client";

/**
 * ProfileSelect — dropdown of saved login profiles, with cookie/origin counts
 * and a per-entry delete action.
 *
 * The dropdown self-refreshes by re-fetching /api/auth-record/profiles after
 * any mutation (delete, or the parent saving a new profile via `refreshKey`).
 */

import { useCallback, useEffect, useState } from "react";
import { Chip } from "../ui/Primitives";
import type { ProfileSummary } from "@/lib/auth/profile";

export function ProfileSelect({
  value,
  onChange,
  refreshKey = 0,
}: {
  value: string | undefined;
  onChange: (id: string | undefined) => void;
  /** Bump this number from the parent to force a re-fetch (after a new save). */
  refreshKey?: number;
}) {
  const [state, setState] = useState<
    | { status: "loading" }
    | { status: "ready"; profiles: ProfileSummary[] }
    | { status: "error"; error: string }
  >({ status: "loading" });

  const refresh = useCallback(async () => {
    setState({ status: "loading" });
    try {
      const r = await fetch("/api/auth-record/profiles");
      const j = await r.json();
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      setState({ status: "ready", profiles: j.profiles ?? [] });
    } catch (e) {
      setState({
        status: "error",
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh, refreshKey]);

  async function onDelete(id: string) {
    if (!confirm(`Delete saved profile "${id}"?`)) return;
    try {
      const r = await fetch(`/api/auth-record/profiles?id=${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      if (value === id) onChange(undefined);
      await refresh();
    } catch (e) {
      alert(`Delete failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  if (state.status === "loading") {
    return (
      <div className="md-body-s text-[color:var(--md-on-surface-variant)]">
        Loading profiles…
      </div>
    );
  }
  if (state.status === "error") {
    return (
      <div className="md-body-s text-[color:var(--md-error)]">
        Failed to load profiles: {state.error}
      </div>
    );
  }
  if (state.profiles.length === 0) {
    return (
      <div className="md-body-s text-[color:var(--md-on-surface-variant)]">
        No saved profiles yet. Capture one below.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <label className="md-label-l text-[color:var(--md-on-surface-variant)]">
        Saved profile
      </label>
      <div className="flex flex-wrap gap-2">
        {state.profiles.map((p) => {
          const selected = p.id === value;
          return (
            <div
              key={p.id}
              className={`glass-thin px-3 py-2 rounded-xl flex items-center gap-2 ${
                selected ? "ring-2 ring-[color:var(--md-primary)]" : ""
              }`}
            >
              <button
                type="button"
                onClick={() => onChange(selected ? undefined : p.id)}
                className="state-layer flex items-center gap-2 -mx-1 px-1 rounded"
                aria-pressed={selected}
              >
                <span className="mono md-label-l">{p.id}</span>
                <Chip className="!h-5 !px-1.5">{p.cookieCount} cookies</Chip>
                {p.domains.length > 0 && (
                  <span
                    className="md-body-s text-[color:var(--md-on-surface-variant)] truncate max-w-[200px]"
                    title={p.domains.join(", ")}
                  >
                    {p.domains.slice(0, 2).join(", ")}
                    {p.domains.length > 2 ? "…" : ""}
                  </span>
                )}
              </button>
              <button
                type="button"
                onClick={() => onDelete(p.id)}
                className="state-layer text-[color:var(--md-error)] md-label-s h-7 w-7 grid place-items-center rounded-full"
                aria-label={`Delete profile ${p.id}`}
                title="Delete profile"
              >
                ✕
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

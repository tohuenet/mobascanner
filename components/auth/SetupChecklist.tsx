"use client";

/**
 * SetupChecklist — pre-flight readiness for browser-capture.
 *
 * Polls /api/setup/auth-record/status and renders one row per requirement
 * (vault key, Chromium binary). When a requirement is missing the user sees
 * an inline "Fix" button instead of a stack-trace error — clicking it kicks
 * off the install via /install-chromium and we keep polling until the binary
 * appears.
 *
 * Lives inline above BrowserCapture so a fresh-install user can go from "?"
 * to "ready" without ever opening a terminal.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "../ui/Primitives";

interface SetupStatus {
  vault: boolean;
  chromium: boolean;
  installing: boolean;
  installLog: string;
  installExitCode?: number | null;
  installError?: string;
  ready: boolean;
}

export function SetupChecklist({
  onReadyChange,
}: {
  /** Parent uses this to disable the Open-browser button until ready. */
  onReadyChange?: (ready: boolean) => void;
}) {
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [error, setError] = useState<string>("");
  const [collapsed, setCollapsed] = useState(false);
  const logRef = useRef<HTMLPreElement | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const r = await fetch("/api/setup/auth-record/status");
      const j = (await r.json()) as SetupStatus | { error: string };
      if (!r.ok || "error" in j) throw new Error(("error" in j && j.error) || `HTTP ${r.status}`);
      setStatus(j);
      setError("");
      onReadyChange?.(j.ready);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      onReadyChange?.(false);
    }
  }, [onReadyChange]);

  useEffect(() => {
    void fetchStatus();
  }, [fetchStatus]);

  // Poll while installing or not yet ready. Stops once we're green.
  useEffect(() => {
    if (!status) return;
    if (status.ready && !status.installing) return;
    const interval = setInterval(() => void fetchStatus(), status.installing ? 1500 : 5000);
    return () => clearInterval(interval);
  }, [status, fetchStatus]);

  // Auto-scroll the install log as new output arrives.
  useEffect(() => {
    if (status?.installing && logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [status?.installLog, status?.installing]);

  const installChromium = useCallback(async () => {
    try {
      await fetch("/api/setup/auth-record/install-chromium", { method: "POST" });
      // Status refresh comes from the polling effect.
      void fetchStatus();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [fetchStatus]);

  if (!status && !error) {
    return (
      <div className="md-body-s text-[color:var(--md-on-surface-variant)]">
        Checking setup…
      </div>
    );
  }
  if (error) {
    return (
      <div className="md-body-s" style={{ color: "var(--md-error)" }}>
        Setup check failed: {error}
      </div>
    );
  }
  const s = status!;

  // Collapsed green state — minimal footprint when everything is ready.
  if (s.ready && collapsed) {
    return (
      <button
        type="button"
        onClick={() => setCollapsed(false)}
        className="state-layer flex items-center gap-2 md-label-l px-2 py-1 rounded-full self-start"
        style={{ color: "var(--md-severity-low)" }}
      >
        <span aria-hidden>✓</span>
        <span>Browser capture ready</span>
        <span className="md-body-s text-[color:var(--md-on-surface-variant)]">(show details)</span>
      </button>
    );
  }

  return (
    <div className="glass-thin p-3 rounded-xl flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="md-label-l">Browser-capture setup</span>
        {s.ready && (
          <button
            type="button"
            onClick={() => setCollapsed(true)}
            className="md-body-s text-[color:var(--md-on-surface-variant)] hover:underline"
          >
            hide
          </button>
        )}
      </div>

      <ChecklistItem
        label="Encrypted vault"
        ok={s.vault}
        okHint="Master key on disk (auto-generated on first use)"
        failHint="Vault unavailable — restart the dev server and retry."
      />

      <ChecklistItem
        label="Chromium binary"
        ok={s.chromium}
        okHint="Playwright Chromium installed"
        failHint={
          s.installing
            ? "Downloading Chromium… this takes a minute on a fast connection."
            : s.installExitCode !== undefined && s.installExitCode !== 0
              ? `Last install exited with code ${s.installExitCode}. Try again.`
              : "Chromium binary not found. One click installs it locally (~150 MB)."
        }
        action={
          !s.chromium && !s.installing ? (
            <Button type="button" variant="tonal" size="sm" onClick={installChromium}>
              Install Chromium
            </Button>
          ) : undefined
        }
      />

      {(s.installing || (s.installLog && !s.chromium)) && (
        <pre
          ref={logRef}
          className="mono md-body-s p-2 rounded-lg max-h-40 overflow-auto whitespace-pre-wrap break-words"
          style={{ background: "color-mix(in oklab, var(--md-on-surface) 5%, transparent)" }}
        >
          {s.installLog || "(starting…)"}
        </pre>
      )}

      {s.installError && (
        <div className="md-body-s" style={{ color: "var(--md-error)" }}>
          {s.installError}
        </div>
      )}
    </div>
  );
}

function ChecklistItem({
  label,
  ok,
  okHint,
  failHint,
  action,
}: {
  label: string;
  ok: boolean;
  okHint: string;
  failHint: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-3">
      <span
        aria-hidden
        className="inline-grid place-items-center w-6 h-6 rounded-full md-label-l shrink-0"
        style={{
          background: ok
            ? "color-mix(in oklab, var(--md-severity-low) 25%, transparent)"
            : "color-mix(in oklab, var(--md-severity-medium) 25%, transparent)",
          color: ok ? "var(--md-severity-low)" : "var(--md-severity-medium)",
        }}
      >
        {ok ? "✓" : "!"}
      </span>
      <div className="flex flex-col flex-1 min-w-0">
        <span className="md-label-l">{label}</span>
        <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
          {ok ? okHint : failHint}
        </span>
      </div>
      {action}
    </div>
  );
}

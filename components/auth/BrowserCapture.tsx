"use client";

/**
 * BrowserCapture — pops open a real Chromium window on the host machine
 * (server-side via Playwright), lets the user log in manually, then captures
 * cookies + localStorage + sessionStorage into the encrypted vault as a named
 * profile.
 *
 * Only works when moba-scanner is running locally (the Chromium window opens
 * on the SAME machine as the Node server). The server returns a clear error
 * if `chromium` isn't installed — `npx playwright install chromium`.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Button, TextField } from "../ui/Primitives";

type Phase =
  | { kind: "idle" }
  | { kind: "starting" }
  | { kind: "recording"; profileId: string; startedAt: number }
  | { kind: "saving" }
  | { kind: "done"; profileId: string; cookieCount: number; originCount: number }
  | { kind: "error"; message: string; hint?: string };

export function BrowserCapture({
  targetUrl,
  onSaved,
  disabled = false,
  disabledHint,
}: {
  targetUrl: string;
  /** Called after a successful save so the parent can refresh ProfileSelect. */
  onSaved: (profileId: string) => void;
  /** When true the Open-browser button is disabled — typically because the
   *  setup checklist hasn't passed yet (no Chromium binary). */
  disabled?: boolean;
  disabledHint?: string;
}) {
  const [profileId, setProfileId] = useState("");
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const recordingRef = useRef<string | null>(null);

  // While recording, poll /api/auth-record so we notice if the user closed
  // the Chromium window manually (session disappears from the active list).
  useEffect(() => {
    if (phase.kind !== "recording") return;
    recordingRef.current = phase.profileId;
    const id = phase.profileId;
    const interval = setInterval(async () => {
      try {
        // GET on /start returns the active-session list; the route reuses the
        // same module that owns the POST that opens them.
        const r = await fetch("/api/auth-record/start");
        const j = await r.json();
        const active: string[] = j.activeSessions ?? [];
        if (!active.includes(id) && recordingRef.current === id) {
          setPhase({
            kind: "error",
            message:
              "Browser session ended before save. If you closed the window manually, start again.",
          });
        }
      } catch {
        /* network blip — keep going */
      }
    }, 2500);
    return () => clearInterval(interval);
  }, [phase]);

  const start = useCallback(async () => {
    const id = profileId.trim();
    if (!id) {
      setPhase({ kind: "error", message: "Profile name required" });
      return;
    }
    if (!targetUrl.startsWith("http")) {
      setPhase({ kind: "error", message: "Enter a target URL first" });
      return;
    }
    setPhase({ kind: "starting" });
    try {
      const r = await fetch("/api/auth-record/start", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ profileId: id, url: targetUrl }),
      });
      const j = await r.json();
      if (!r.ok) {
        setPhase({
          kind: "error",
          message: j.error ?? `HTTP ${r.status}`,
          hint: j.hint,
        });
        return;
      }
      setPhase({ kind: "recording", profileId: id, startedAt: Date.now() });
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }, [profileId, targetUrl]);

  const save = useCallback(async () => {
    if (phase.kind !== "recording") return;
    const id = phase.profileId;
    setPhase({ kind: "saving" });
    try {
      const r = await fetch("/api/auth-record/save", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ profileId: id }),
      });
      const j = await r.json();
      if (!r.ok) {
        setPhase({ kind: "error", message: j.error ?? `HTTP ${r.status}` });
        return;
      }
      recordingRef.current = null;
      setPhase({
        kind: "done",
        profileId: id,
        cookieCount: j.cookieCount ?? 0,
        originCount: j.originCount ?? 0,
      });
      onSaved(id);
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }, [phase, onSaved]);

  const cancel = useCallback(async () => {
    if (phase.kind !== "recording") return;
    const id = phase.profileId;
    try {
      await fetch(`/api/auth-record/save?profileId=${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
    } catch {
      /* best effort */
    }
    recordingRef.current = null;
    setPhase({ kind: "idle" });
  }, [phase]);

  return (
    <div className="glass-thin p-3 rounded-xl flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <span className="md-label-l">Capture a new login session</span>
        <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
          opens Chromium on this machine — only works when self-hosted locally
        </span>
      </div>

      {phase.kind === "idle" || phase.kind === "error" || phase.kind === "done" ? (
        <div className="flex flex-wrap gap-2 items-end">
          <TextField
            label="Profile name"
            placeholder="e.g. staging-admin"
            value={profileId}
            onChange={(e) => setProfileId(e.target.value)}
            hint="A short identifier you'll pick from later."
            className="flex-1 min-w-[200px]"
          />
          <Button
            type="button"
            variant="tonal"
            onClick={start}
            disabled={disabled || !profileId.trim() || !targetUrl.startsWith("http")}
            title={disabled ? disabledHint : undefined}
          >
            ▶ Open browser to log in
          </Button>
        </div>
      ) : null}
      {disabled && disabledHint && (phase.kind === "idle" || phase.kind === "error") && (
        <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
          {disabledHint}
        </span>
      )}

      {phase.kind === "starting" && (
        <div className="md-body-s text-[color:var(--md-on-surface-variant)]">
          Spawning Chromium…
        </div>
      )}

      {phase.kind === "recording" && (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <span
              aria-hidden
              className="inline-block w-2 h-2 rounded-full"
              style={{ background: "var(--md-severity-low)" }}
            />
            <span className="md-body-m">
              Browser is open — log in inside the Chromium window, then click
              Save below.
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="filled" onClick={save}>
              ✓ Save session
            </Button>
            <Button type="button" variant="outlined" onClick={cancel}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      {phase.kind === "saving" && (
        <div className="md-body-s text-[color:var(--md-on-surface-variant)]">
          Saving storage state…
        </div>
      )}

      {phase.kind === "done" && (
        <div className="md-body-s" style={{ color: "var(--md-severity-low)" }}>
          ✓ Saved profile <span className="mono">{phase.profileId}</span> —{" "}
          {phase.cookieCount} cookies, {phase.originCount} origins.
        </div>
      )}

      {phase.kind === "error" && (
        <div className="flex flex-col gap-1">
          <span className="md-body-s" style={{ color: "var(--md-error)" }}>
            {phase.message}
          </span>
          {phase.hint && (
            <span className="md-body-s text-[color:var(--md-on-surface-variant)] mono">
              → {phase.hint}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

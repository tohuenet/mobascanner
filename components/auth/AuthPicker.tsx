"use client";

/**
 * AuthPicker — single component the scan-setup page drops in to handle every
 * form of target authentication: none, manually-pasted headers/bearer, or a
 * captured browser session.
 *
 * Controlled component — parent owns the value. On submit the parent reads
 * value.mode and forwards either `headers`+`bearer` or `profileId` to the
 * scan API. The mode you don't pick is hidden so users aren't tempted to
 * fill in conflicting auth.
 */

import { useState } from "react";
import { Chip } from "../ui/Primitives";
import { BrowserCapture } from "./BrowserCapture";
import { ProfileSelect } from "./ProfileSelect";
import { SetupChecklist } from "./SetupChecklist";

export type AuthMode = "none" | "manual" | "profile";

export interface AuthValue {
  mode: AuthMode;
  /** Raw lines of "Key: value", one per line (manual mode). */
  headers?: string;
  /** Bearer token (manual mode). */
  bearer?: string;
  /** Selected profile id (profile mode). */
  profileId?: string;
}

const MODE_LABELS: Array<{ id: AuthMode; label: string; description: string }> = [
  { id: "none", label: "No auth", description: "Public surface only" },
  { id: "manual", label: "Headers / bearer", description: "Paste tokens or cookies" },
  { id: "profile", label: "Captured session", description: "Log in once via browser" },
];

export function AuthPicker({
  value,
  onChange,
  targetUrl,
}: {
  value: AuthValue;
  onChange: (next: AuthValue) => void;
  /** Needed by BrowserCapture so the spawned Chromium opens on the target. */
  targetUrl: string;
}) {
  // Bumped after a new profile saves; ProfileSelect re-fetches on change.
  const [profilesRefresh, setProfilesRefresh] = useState(0);
  // Mirrored from SetupChecklist so BrowserCapture's Open button can disable
  // when prerequisites (vault, Chromium) aren't satisfied yet.
  const [setupReady, setSetupReady] = useState(false);

  const setMode = (mode: AuthMode) => onChange({ ...value, mode });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="md-label-l text-[color:var(--md-on-surface-variant)]">
          Authentication
        </span>
        <div className="flex gap-1 flex-wrap" role="radiogroup" aria-label="Auth mode">
          {MODE_LABELS.map((m) => (
            <Chip
              key={m.id}
              selected={value.mode === m.id}
              onClick={() => setMode(m.id)}
              role="radio"
              aria-checked={value.mode === m.id}
              tabIndex={0}
              title={m.description}
            >
              {m.label}
            </Chip>
          ))}
        </div>
      </div>

      {value.mode === "manual" && (
        <div className="flex flex-col gap-3">
          <div>
            <label className="md-label-l text-[color:var(--md-on-surface-variant)]">
              Custom request headers (one per line, key: value)
            </label>
            <textarea
              value={value.headers ?? ""}
              onChange={(e) => onChange({ ...value, headers: e.target.value })}
              rows={4}
              placeholder="X-API-Key: secret123&#10;Cookie: session=abc"
              className="mono w-full mt-1.5 px-3 py-2 rounded-xl border border-[color:var(--md-outline-variant)] focus-within:border-[color:var(--md-primary)] outline-none bg-[color-mix(in_oklab,var(--md-surface-container-low)_80%,transparent)] md-body-m"
            />
          </div>
          <div>
            <label className="md-label-l text-[color:var(--md-on-surface-variant)]">
              Bearer token (optional)
            </label>
            <input
              type="text"
              value={value.bearer ?? ""}
              onChange={(e) => onChange({ ...value, bearer: e.target.value })}
              placeholder="eyJ..."
              className="mono w-full mt-1.5 px-3 py-2 rounded-xl border border-[color:var(--md-outline-variant)] focus-within:border-[color:var(--md-primary)] outline-none bg-[color-mix(in_oklab,var(--md-surface-container-low)_80%,transparent)] md-body-m"
            />
          </div>
        </div>
      )}

      {value.mode === "profile" && (
        <div className="flex flex-col gap-4">
          <SetupChecklist onReadyChange={setSetupReady} />
          <ProfileSelect
            value={value.profileId}
            onChange={(id) => onChange({ ...value, profileId: id })}
            refreshKey={profilesRefresh}
          />
          <BrowserCapture
            targetUrl={targetUrl}
            disabled={!setupReady}
            disabledHint="Complete the setup checklist above first."
            onSaved={(id) => {
              onChange({ ...value, profileId: id });
              setProfilesRefresh((n) => n + 1);
            }}
          />
        </div>
      )}

      {value.mode === "none" && (
        <p className="md-body-s text-[color:var(--md-on-surface-variant)]">
          Scanners will probe the public surface only. Pages behind a login
          won&apos;t be reached.
        </p>
      )}
    </div>
  );
}

"use client";

/**
 * Manual light / dark / system theme control (T3.1).
 *
 * Cycles light → dark → system, persists the choice to localStorage under
 * `moba-theme`, and stamps it onto <html data-theme> (the same key/attribute the
 * pre-hydration script in app/layout.tsx reads, so there's no FOUC on reload).
 * "system" clears to the OS preference via @media (prefers-color-scheme) in
 * globals.css — no JS listener needed, the media query tracks the OS live.
 *
 * The preference is read through useSyncExternalStore: the server snapshot is
 * "system" (matching SSR), and React swaps in the real localStorage value on the
 * client before paint with no hydration mismatch and no setState-in-effect. A
 * DOM-sync effect mirrors the current choice onto <html data-theme>, so a change
 * in another tab (via the `storage` event) stays consistent here too.
 */

import * as React from "react";

type Theme = "light" | "dark" | "system";

const NEXT: Record<Theme, Theme> = { light: "dark", dark: "system", system: "light" };
const LABEL: Record<Theme, string> = { light: "Light", dark: "Dark", system: "System" };
const STORAGE_KEY = "moba-theme";
/** Fired in-tab after we write localStorage (the native `storage` event only
 *  reaches OTHER tabs), so useSyncExternalStore re-reads the new value. */
const CHANGE_EVENT = "moba-theme-change";

function readStored(): Theme {
  try {
    const t = localStorage.getItem(STORAGE_KEY);
    if (t === "light" || t === "dark" || t === "system") return t;
  } catch {
    /* ignore */
  }
  return "system";
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener("storage", onChange);
  window.addEventListener(CHANGE_EVENT, onChange);
  return () => {
    window.removeEventListener("storage", onChange);
    window.removeEventListener(CHANGE_EVENT, onChange);
  };
}

function ThemeIcon({ theme }: { theme: Theme }) {
  const common = {
    width: 18,
    height: 18,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };
  if (theme === "light") {
    return (
      <svg {...common}>
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
      </svg>
    );
  }
  if (theme === "dark") {
    return (
      <svg {...common}>
        <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
    </svg>
  );
}

export function ThemeToggle({ className = "" }: { className?: string }) {
  const theme = React.useSyncExternalStore<Theme>(subscribe, readStored, () => "system");

  // Keep <html data-theme> in lockstep with the resolved preference (covers the
  // first client render and cross-tab changes). A DOM write, not setState.
  React.useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const cycle = React.useCallback(() => {
    const next = NEXT[readStored()];
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* ignore */
    }
    document.documentElement.setAttribute("data-theme", next);
    window.dispatchEvent(new Event(CHANGE_EVENT));
  }, []);

  return (
    <button
      type="button"
      onClick={cycle}
      aria-label={`Theme: ${LABEL[theme]}. Activate to switch to ${LABEL[NEXT[theme]]}.`}
      title={`Theme: ${LABEL[theme]}`}
      className={`state-layer inline-flex items-center gap-2 h-9 px-2.5 rounded-full border border-[color:var(--md-outline-variant)] text-[color:var(--md-on-surface)] ${className}`}
    >
      <ThemeIcon theme={theme} />
      <span className="md-label-l hidden sm:inline">{LABEL[theme]}</span>
    </button>
  );
}

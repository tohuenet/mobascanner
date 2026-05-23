"use client";

/**
 * Tabs — single-row segmented control that syncs the active tab to ?tab=<id>
 * in the URL so refreshes/deep-links land on the same panel.
 *
 * Keyboard: Arrow Left/Right cycle, Home/End jump. ARIA roles wired so screen
 * readers announce tab/panel changes.
 *
 * Render-prop API: callers pass a function that returns the panel content for
 * the active tab, keeping Tabs decoupled from any specific tab's data shape.
 */

import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";

export interface TabItem {
  id: string;
  label: string;
  /** Optional badge (count) shown to the right of the label. */
  badge?: number | string;
}

interface TabsProps {
  tabs: TabItem[];
  defaultId: string;
  children: (activeId: string) => React.ReactNode;
  /** aria-label on the tablist. */
  ariaLabel?: string;
}

export function Tabs({ tabs, defaultId, children, ariaLabel = "Sections" }: TabsProps) {
  const router = useRouter();
  const sp = useSearchParams();
  const param = sp.get("tab");
  const activeId = tabs.some((t) => t.id === param) ? (param as string) : defaultId;

  const setActive = React.useCallback(
    (id: string) => {
      const next = new URLSearchParams(sp.toString());
      next.set("tab", id);
      // Replace, don't push — tab switching shouldn't bloat history.
      router.replace(`?${next.toString()}`, { scroll: false });
    },
    [router, sp],
  );

  const onKeyDown: React.KeyboardEventHandler<HTMLDivElement> = (e) => {
    const idx = tabs.findIndex((t) => t.id === activeId);
    if (idx < 0) return;
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      const dir = e.key === "ArrowRight" ? 1 : -1;
      setActive(tabs[(idx + dir + tabs.length) % tabs.length].id);
    } else if (e.key === "Home") {
      e.preventDefault();
      setActive(tabs[0].id);
    } else if (e.key === "End") {
      e.preventDefault();
      setActive(tabs[tabs.length - 1].id);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div
        role="tablist"
        aria-label={ariaLabel}
        onKeyDown={onKeyDown}
        className="flex items-center gap-1 border-b border-[color:var(--md-outline-variant)] overflow-x-auto"
      >
        {tabs.map((t) => {
          const active = t.id === activeId;
          return (
            <button
              key={t.id}
              role="tab"
              id={`tab-${t.id}`}
              type="button"
              aria-selected={active}
              aria-controls={`tabpanel-${t.id}`}
              tabIndex={active ? 0 : -1}
              onClick={() => setActive(t.id)}
              className={`state-layer relative inline-flex items-center gap-2 px-4 h-11 md-label-l transition-colors whitespace-nowrap ${
                active
                  ? "text-[color:var(--md-primary)]"
                  : "text-[color:var(--md-on-surface-variant)] hover:text-[color:var(--md-on-surface)]"
              }`}
            >
              <span>{t.label}</span>
              {t.badge !== undefined && t.badge !== 0 && (
                <span
                  className="inline-grid place-items-center min-w-[1.25rem] h-5 px-1.5 rounded-full md-label-s"
                  style={{
                    background: active
                      ? "var(--md-primary)"
                      : "color-mix(in oklab, var(--md-on-surface) 12%, transparent)",
                    color: active
                      ? "var(--md-on-primary)"
                      : "var(--md-on-surface-variant)",
                  }}
                >
                  {t.badge}
                </span>
              )}
              <span
                aria-hidden
                className="absolute left-2 right-2 bottom-0 h-0.5 rounded-full transition-opacity"
                style={{
                  background: "var(--md-primary)",
                  opacity: active ? 1 : 0,
                }}
              />
            </button>
          );
        })}
      </div>

      <div
        role="tabpanel"
        id={`tabpanel-${activeId}`}
        aria-labelledby={`tab-${activeId}`}
        // Mounting each tab fresh on switch keeps the DOM lean. Tabs holding
        // long-lived state (SSE listeners) live on the parent, not in tabs.
      >
        {children(activeId)}
      </div>
    </div>
  );
}

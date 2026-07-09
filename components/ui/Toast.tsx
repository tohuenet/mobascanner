"use client";

/**
 * Minimal, dependency-free toast system (T3.3).
 *
 * Mounted once in AppShell so every surface shares one accessible notification
 * channel. The viewport is a persistent aria-live region (role="status"), so
 * toasts pushed into it are announced without stealing focus; each auto-dismisses
 * and can be closed manually. Replaces ScanHeader's hand-rolled absolute toast.
 */

import * as React from "react";

type ToastTone = "info" | "success" | "error";

interface ToastItem {
  id: number;
  message: string;
  tone: ToastTone;
}

interface ToastOptions {
  tone?: ToastTone;
  /** Auto-dismiss delay in ms. */
  duration?: number;
}

interface ToastContextValue {
  toast: (message: string, opts?: ToastOptions) => void;
}

const ToastContext = React.createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const ctx = React.useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within <ToastProvider>");
  return ctx;
}

function toneColor(tone: ToastTone): string {
  switch (tone) {
    case "success":
      return "var(--md-severity-low)";
    case "error":
      return "var(--md-error)";
    default:
      return "var(--md-primary)";
  }
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = React.useState<ToastItem[]>([]);
  const timers = React.useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());
  const idRef = React.useRef(0);

  const dismiss = React.useCallback((id: number) => {
    setItems((prev) => prev.filter((t) => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
  }, []);

  const toast = React.useCallback<ToastContextValue["toast"]>(
    (message, opts) => {
      const id = (idRef.current += 1);
      const tone = opts?.tone ?? "info";
      const duration = opts?.duration ?? 3500;
      setItems((prev) => [...prev, { id, message, tone }]);
      const timer = setTimeout(() => dismiss(id), duration);
      timers.current.set(id, timer);
    },
    [dismiss],
  );

  // Clear any pending timers if the provider unmounts.
  React.useEffect(() => {
    const timersMap = timers.current;
    return () => {
      timersMap.forEach((t) => clearTimeout(t));
      timersMap.clear();
    };
  }, []);

  const value = React.useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        role="status"
        aria-live="polite"
        className="fixed z-[60] bottom-4 right-4 flex flex-col gap-2 w-80 max-w-[calc(100vw-2rem)] pointer-events-none print:hidden"
      >
        {items.map((t) => {
          const color = toneColor(t.tone);
          return (
            <div
              key={t.id}
              className="toast-item glass-strong pointer-events-auto flex items-start gap-2.5 p-3 pr-2"
              style={{ borderLeft: `3px solid ${color}` }}
            >
              <span className="sev-dot mt-1.5 shrink-0" style={{ background: color, color }} />
              <span className="md-body-s flex-1 min-w-0 text-[color:var(--md-on-surface)]">{t.message}</span>
              <button
                type="button"
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss notification"
                className="state-layer shrink-0 grid place-items-center w-6 h-6 rounded-full text-[color:var(--md-on-surface-variant)]"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M18 6 6 18M6 6l12 12" />
                </svg>
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

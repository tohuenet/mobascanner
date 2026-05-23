"use client";

/**
 * LogsTab — streaming log viewer. Used to be a collapsible block under the
 * scanner progress; promoted to a tab so we can give it real estate and add
 * filter controls without crowding the main page.
 */

import { useMemo, useState } from "react";
import { Chip } from "../ui/Primitives";

type LogLevel = "info" | "warn" | "error";
type LogLine = { at: number; level: string; message: string };

const LEVELS: Array<LogLevel | "all"> = ["all", "info", "warn", "error"];

export function LogsTab({ logs }: { logs: LogLine[] }) {
  const [level, setLevel] = useState<LogLevel | "all">("all");
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return logs.filter((l) => {
      if (level !== "all" && l.level !== level) return false;
      if (q && !l.message.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [logs, level, query]);

  return (
    <div className="flex flex-col gap-3">
      <div className="glass p-3 flex flex-wrap gap-2 items-center">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter log lines…"
          className="bg-transparent outline-none px-3 h-9 rounded-full border border-[color:var(--md-outline-variant)] focus:border-[color:var(--md-primary)] md-body-m flex-1 min-w-[200px]"
        />
        <div className="flex gap-1">
          {LEVELS.map((l) => (
            <Chip
              key={l}
              selected={level === l}
              onClick={() => setLevel(l)}
              role="button"
              tabIndex={0}
            >
              {l}
            </Chip>
          ))}
        </div>
        <span className="md-body-s text-[color:var(--md-on-surface-variant)] ml-auto">
          {filtered.length} / {logs.length} lines
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="glass-thin p-10 text-center text-[color:var(--md-on-surface-variant)]">
          {logs.length === 0 ? "No log lines yet." : "No lines match the current filter."}
        </div>
      ) : (
        <pre className="mono md-body-s p-3 rounded-xl bg-[color-mix(in_oklab,var(--md-on-surface)_5%,transparent)] max-h-[60vh] overflow-auto whitespace-pre-wrap break-words">
          {filtered
            .map(
              (l) =>
                `[${new Date(l.at).toLocaleTimeString()}] ${l.level
                  .toUpperCase()
                  .padEnd(5)} ${l.message}`,
            )
            .join("\n")}
        </pre>
      )}
    </div>
  );
}

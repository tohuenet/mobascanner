"use client";

import { useState } from "react";
import { SeverityBadge, Chip } from "./ui/Primitives";
import type { Finding, Severity } from "@/lib/types";

const RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function FindingsList({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [scannerFilter, setScannerFilter] = useState<string | "all">("all");
  const [query, setQuery] = useState("");

  const scanners = Array.from(new Set(findings.map((f) => f.scannerName))).sort();

  const filtered = findings
    .filter((f) => filter === "all" || f.severity === filter)
    .filter((f) => scannerFilter === "all" || f.scannerName === scannerFilter)
    .filter((f) => {
      if (!query.trim()) return true;
      const q = query.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        (f.location.url ?? "").toLowerCase().includes(q) ||
        (f.location.file ?? "").toLowerCase().includes(q) ||
        (f.ruleId ?? "").toLowerCase().includes(q)
      );
    })
    .sort((a, b) => RANK[b.severity] - RANK[a.severity]);

  return (
    <div className="flex flex-col gap-3">
      <div className="glass p-3 flex flex-wrap gap-2 items-center">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search findings…"
          className="bg-transparent outline-none px-3 h-9 rounded-full border border-[color:var(--md-outline-variant)] focus:border-[color:var(--md-primary)] md-body-m flex-1 min-w-[200px]"
        />
        <div className="flex gap-1">
          {(["all", "critical", "high", "medium", "low", "info"] as const).map((s) => (
            <Chip
              key={s}
              selected={filter === s}
              onClick={() => setFilter(s as typeof filter)}
              role="button"
              tabIndex={0}
            >
              {s}
            </Chip>
          ))}
        </div>
        {scanners.length > 1 && (
          <select
            value={scannerFilter}
            onChange={(e) => setScannerFilter(e.target.value)}
            className="bg-transparent border border-[color:var(--md-outline-variant)] focus:border-[color:var(--md-primary)] rounded-full h-9 px-3 md-body-m outline-none"
          >
            <option value="all">all scanners</option>
            {scanners.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        )}
      </div>

      {filtered.length === 0 ? (
        <div className="glass-thin p-10 text-center text-[color:var(--md-on-surface-variant)]">
          {findings.length === 0 ? "No findings yet." : "No findings match the current filter."}
        </div>
      ) : (
        filtered.map((f) => <FindingCard key={f.id} f={f} />)
      )}
    </div>
  );
}

function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const loc = f.location.file
    ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}`
    : f.location.url ?? "";

  return (
    <article className="glass overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full text-left flex items-start gap-3 p-4 state-layer"
      >
        <SeverityBadge severity={f.severity} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="md-title-m flex-1 min-w-0 break-words">{f.title}</h3>
            <Chip className="!h-6 !px-2">{f.scannerName}</Chip>
            {f.confidence && <Chip className="!h-6 !px-2">conf: {f.confidence}</Chip>}
          </div>
          {loc && (
            <p className="md-body-s mono text-[color:var(--md-on-surface-variant)] mt-1 break-all">
              {loc}
            </p>
          )}
        </div>
        <span
          className="text-[color:var(--md-on-surface-variant)] transition-transform"
          style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
          aria-hidden
        >
          ▾
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4 grid gap-3">
          {f.description && <p className="md-body-m whitespace-pre-wrap">{f.description}</p>}

          <div className="flex flex-wrap gap-1.5 md-body-s">
            {f.ruleId && <Chip className="!h-6 !px-2">rule: {f.ruleId}</Chip>}
            {f.cvss !== undefined && <Chip className="!h-6 !px-2">CVSS {f.cvss}</Chip>}
            {f.cve?.map((c) => <Chip key={c} className="!h-6 !px-2">{c}</Chip>)}
            {f.cwe?.map((c) => <Chip key={c} className="!h-6 !px-2">{c}</Chip>)}
            {f.owasp?.map((c) => <Chip key={c} className="!h-6 !px-2">OWASP {c}</Chip>)}
          </div>

          {f.location.snippet && (
            <pre className="mono md-body-s p-3 rounded-lg bg-[color-mix(in_oklab,var(--md-on-surface)_5%,transparent)] overflow-x-auto whitespace-pre-wrap break-words">
              {f.location.snippet}
            </pre>
          )}

          {f.remediation && (
            <div className="glass-thin p-3">
              <span className="md-label-l">Remediation</span>
              <p className="md-body-m mt-1 whitespace-pre-wrap">{f.remediation}</p>
            </div>
          )}

          {f.references && f.references.length > 0 && (
            <div>
              <span className="md-label-l text-[color:var(--md-on-surface-variant)]">References</span>
              <ul className="grid gap-1 mt-1">
                {f.references.map((r, i) => (
                  <li key={i}>
                    <a href={r} target="_blank" rel="noopener noreferrer" className="md-body-s text-[color:var(--md-primary)] hover:underline break-all">{r}</a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {f.evidence && Object.keys(f.evidence).length > 0 && (
            <details className="glass-thin p-3">
              <summary className="md-label-l cursor-pointer">Evidence</summary>
              <pre className="mono md-body-s mt-2 overflow-x-auto whitespace-pre-wrap break-words">
                {JSON.stringify(f.evidence, null, 2)}
              </pre>
            </details>
          )}
        </div>
      )}
    </article>
  );
}

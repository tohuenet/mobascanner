"use client";

/**
 * FindingsList — the navigable, triage-friendly list of findings.
 *
 * Filtering/sorting model:
 *   - Severity is URL-driven (`?sev=`) so the SeverityCounters tiles, the filter
 *     chips here, and any shared link stay in sync. Everything else (scanner,
 *     search, sort, group-by, triage-state) is local UI state.
 *   - Chips show per-severity counts computed over the *other* active filters
 *     (faceted-search style) and dim to zero when nothing would match.
 *
 * Deep-linking: every card carries a stable `#f-<id>` anchor. On mount (and on
 * hashchange) a matching hash opens that card and scrolls to it. The setState is
 * deferred to `requestAnimationFrame` — both so the target is painted before we
 * scroll and to avoid the "setState synchronously within an effect" lint rule.
 *
 * Backward compatibility: the public API is still `<FindingsList findings={…} />`.
 */

import { useEffect, useRef, useState, type ReactNode } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { SeverityBadge, Chip } from "./ui/Primitives";
import type { Finding, Severity } from "@/lib/types";

const RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const CONF_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

type SortKey = "severity" | "cvss" | "confidence" | "scanner" | "newest";
type GroupKey = "none" | "scanner" | "severity" | "location";
type TriageState = "open" | "false-positive" | "fixed" | "accepted-risk";
type TriageFilter = "all" | TriageState;

const SORT_LABELS: Record<SortKey, string> = {
  severity: "Severity",
  cvss: "CVSS",
  confidence: "Confidence",
  scanner: "Scanner",
  newest: "Newest",
};
const GROUP_LABELS: Record<GroupKey, string> = {
  none: "No grouping",
  scanner: "Group: scanner",
  severity: "Group: severity",
  location: "Group: location",
};
const TRIAGE_LABELS: Record<TriageFilter, string> = {
  all: "All states",
  open: "Open",
  "false-positive": "False positive",
  fixed: "Fixed",
  "accepted-risk": "Accepted risk",
};

/** Findings with no explicit triage are treated as "open". */
function triageState(f: Finding): TriageState {
  return (f.triage?.state as TriageState) ?? "open";
}

function comparator(key: SortKey): (a: Finding, b: Finding) => number {
  switch (key) {
    case "cvss":
      return (a, b) => (b.cvss ?? -1) - (a.cvss ?? -1) || RANK[b.severity] - RANK[a.severity];
    case "confidence":
      return (a, b) =>
        (CONF_RANK[b.confidence] ?? 0) - (CONF_RANK[a.confidence] ?? 0) ||
        RANK[b.severity] - RANK[a.severity];
    case "scanner":
      return (a, b) => a.scannerName.localeCompare(b.scannerName) || RANK[b.severity] - RANK[a.severity];
    case "newest":
      return (a, b) => b.createdAt - a.createdAt;
    case "severity":
    default:
      return (a, b) => RANK[b.severity] - RANK[a.severity] || b.createdAt - a.createdAt;
  }
}

function groupKeyOf(f: Finding, group: GroupKey): string {
  switch (group) {
    case "scanner":
      return f.scannerName;
    case "severity":
      return f.severity;
    case "location":
      return f.location.url ?? f.location.file ?? "(no location)";
    default:
      return "";
  }
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  const router = useRouter();
  const sp = useSearchParams();

  // Severity filter lives in the URL so it stays in sync with the counters.
  const sevParam = sp.get("sev");
  const severity: Severity | "all" =
    sevParam && (SEVERITIES as string[]).includes(sevParam) ? (sevParam as Severity) : "all";

  const [scannerFilter, setScannerFilter] = useState<string | "all">("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortKey>("severity");
  const [group, setGroup] = useState<GroupKey>("none");
  const [triage, setTriage] = useState<TriageFilter>("all");
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set());

  // Open + scroll to a #f-<id> deep link on mount / hashchange.
  useEffect(() => {
    function applyHash() {
      const m = /^#f-(.+)$/.exec(window.location.hash);
      if (!m) return;
      const id = m[1];
      requestAnimationFrame(() => {
        setOpenIds((prev) => (prev.has(id) ? prev : new Set(prev).add(id)));
        document.getElementById(`f-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
    applyHash();
    window.addEventListener("hashchange", applyHash);
    return () => window.removeEventListener("hashchange", applyHash);
  }, []);

  function setSeverity(s: Severity | "all") {
    const next = new URLSearchParams(sp.toString());
    if (s === "all") next.delete("sev");
    else next.set("sev", s);
    router.replace(`?${next.toString()}`, { scroll: false });
  }

  function toggleOpen(id: string) {
    setOpenIds((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  }

  const scanners = Array.from(new Set(findings.map((f) => f.scannerName))).sort();

  // Everything except the severity facet, so chip counts reflect the rest.
  const base = findings
    .filter((f) => scannerFilter === "all" || f.scannerName === scannerFilter)
    .filter((f) => triage === "all" || triageState(f) === triage)
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
    });

  const sevCounts = SEVERITIES.reduce(
    (acc, s) => ({ ...acc, [s]: base.filter((f) => f.severity === s).length }),
    {} as Record<Severity, number>,
  );

  const filtered = base
    .filter((f) => severity === "all" || f.severity === severity)
    .slice()
    .sort(comparator(sort));

  return (
    <div className="flex flex-col gap-3">
      <div className="glass p-3 flex flex-col gap-3 print:hidden">
        <div className="flex flex-wrap gap-2 items-center">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings…"
            aria-label="Search findings"
            className="bg-transparent outline-none px-3 h-9 rounded-full border border-[color:var(--md-outline-variant)] focus:border-[color:var(--md-primary)] md-body-m flex-1 min-w-[200px]"
          />
          <div className="flex gap-1 flex-wrap" role="group" aria-label="Filter by severity">
            <Chip
              selected={severity === "all"}
              onClick={() => setSeverity("all")}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setSeverity("all");
                }
              }}
            >
              all {base.length}
            </Chip>
            {SEVERITIES.map((s) => {
              const n = sevCounts[s];
              return (
                <Chip
                  key={s}
                  selected={severity === s}
                  onClick={() => setSeverity(s)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setSeverity(s);
                    }
                  }}
                  className={n === 0 ? "opacity-40" : ""}
                >
                  {s} {n}
                </Chip>
              );
            })}
          </div>
        </div>

        <div className="flex flex-wrap gap-2 items-center">
          {scanners.length > 1 && (
            <FilterSelect
              label="Scanner"
              value={scannerFilter}
              onChange={(v) => setScannerFilter(v)}
              options={[["all", "All scanners"], ...scanners.map((s) => [s, s] as [string, string])]}
            />
          )}
          <FilterSelect
            label="Sort"
            value={sort}
            onChange={(v) => setSort(v as SortKey)}
            options={(Object.keys(SORT_LABELS) as SortKey[]).map((k) => [k, SORT_LABELS[k]])}
          />
          <FilterSelect
            label="Group"
            value={group}
            onChange={(v) => setGroup(v as GroupKey)}
            options={(Object.keys(GROUP_LABELS) as GroupKey[]).map((k) => [k, GROUP_LABELS[k]])}
          />
          <FilterSelect
            label="Triage state"
            value={triage}
            onChange={(v) => setTriage(v as TriageFilter)}
            options={(Object.keys(TRIAGE_LABELS) as TriageFilter[]).map((k) => [k, TRIAGE_LABELS[k]])}
          />
          <span className="md-body-s text-[color:var(--md-on-surface-variant)] ml-auto">
            {filtered.length} / {findings.length} shown
          </span>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="glass-thin p-10 text-center text-[color:var(--md-on-surface-variant)]">
          {findings.length === 0 ? "No findings yet." : "No findings match the current filter."}
        </div>
      ) : group === "none" ? (
        filtered.map((f) => (
          <FindingCard key={f.id} f={f} open={openIds.has(f.id)} onToggle={() => toggleOpen(f.id)} />
        ))
      ) : (
        <GroupedFindings
          findings={filtered}
          group={group}
          openIds={openIds}
          onToggle={toggleOpen}
        />
      )}
    </div>
  );
}

function GroupedFindings({
  findings,
  group,
  openIds,
  onToggle,
}: {
  findings: Finding[];
  group: GroupKey;
  openIds: Set<string>;
  onToggle: (id: string) => void;
}) {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const k = groupKeyOf(f, group);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k)!.push(f);
  }
  const ordered =
    group === "severity"
      ? [...groups.entries()].sort((a, b) => RANK[b[0] as Severity] - RANK[a[0] as Severity])
      : [...groups.entries()].sort((a, b) => b[1].length - a[1].length);

  return (
    <div className="flex flex-col gap-3">
      {ordered.map(([label, items]) => (
        <details key={label} open className="glass-thin p-2">
          <summary className="cursor-pointer flex items-center gap-2 px-1 py-1 md-label-l">
            {group === "severity" ? (
              <SeverityBadge severity={label as Severity} />
            ) : (
              <span className={`break-all min-w-0 flex-1 ${group === "location" ? "mono md-body-s" : ""}`}>
                {label}
              </span>
            )}
            <Chip className="!h-6 !px-2 shrink-0">{items.length}</Chip>
          </summary>
          <div className="mt-2 flex flex-col gap-2">
            {items.map((f) => (
              <FindingCard key={f.id} f={f} open={openIds.has(f.id)} onToggle={() => onToggle(f.id)} />
            ))}
          </div>
        </details>
      ))}
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
}) {
  return (
    <label className="flex items-center gap-1.5">
      <span className="sr-only">{label}</span>
      <select
        value={value}
        aria-label={label}
        onChange={(e) => onChange(e.target.value)}
        className="bg-transparent border border-[color:var(--md-outline-variant)] focus:border-[color:var(--md-primary)] rounded-full h-9 px-3 md-body-m outline-none"
      >
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </label>
  );
}

function buildMarkdown(f: Finding): string {
  const loc = f.location.file
    ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}`
    : f.location.url ?? "(no location)";
  const lines = [
    `## ${f.title}`,
    "",
    `- **Severity:** ${f.severity}`,
    `- **Confidence:** ${f.confidence}`,
    `- **Location:** ${loc}`,
  ];
  if (f.ruleId) lines.push(`- **Rule:** ${f.ruleId}`);
  if (f.cvss !== undefined) lines.push(`- **CVSS:** ${f.cvss}`);
  if (f.cwe?.length) lines.push(`- **CWE:** ${f.cwe.join(", ")}`);
  if (f.owasp?.length) lines.push(`- **OWASP:** ${f.owasp.join(", ")}`);
  lines.push("", f.description || "(no description)");
  if (f.remediation) lines.push("", "**Remediation**", "", f.remediation);
  return lines.join("\n");
}

function FindingCard({
  f,
  open,
  onToggle,
}: {
  f: Finding;
  open: boolean;
  onToggle: () => void;
}) {
  const [copied, setCopied] = useState<"" | "link" | "md">("");
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (copyTimer.current) clearTimeout(copyTimer.current);
  }, []);

  function flash(which: "link" | "md") {
    setCopied(which);
    if (copyTimer.current) clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(""), 1600);
  }

  async function copyLink() {
    const url = `${window.location.origin}${window.location.pathname}?tab=findings&sev=all#f-${f.id}`;
    try {
      await navigator.clipboard.writeText(url);
      flash("link");
    } catch {
      /* clipboard blocked — no-op */
    }
  }

  async function copyMarkdown() {
    try {
      await navigator.clipboard.writeText(buildMarkdown(f));
      flash("md");
    } catch {
      /* clipboard blocked — no-op */
    }
  }

  const loc = f.location.file
    ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}`
    : f.location.url ?? "";
  const state = triageState(f);

  return (
    <article id={`f-${f.id}`} className="glass overflow-hidden scroll-mt-24">
      <button
        onClick={onToggle}
        aria-expanded={open}
        className="w-full text-left flex items-start gap-3 p-4 state-layer"
      >
        <SeverityBadge severity={f.severity} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="md-title-m flex-1 min-w-0 break-words">{f.title}</h3>
            <Chip className="!h-6 !px-2">{f.scannerName}</Chip>
            {f.confidence && <Chip className="!h-6 !px-2">conf: {f.confidence}</Chip>}
            {state !== "open" && (
              <Chip className="!h-6 !px-2" selected>
                {state}
              </Chip>
            )}
          </div>
          {loc && (
            <p className="md-body-s mono text-[color:var(--md-on-surface-variant)] mt-1 break-all">
              {loc}
            </p>
          )}
        </div>
        <span
          className="text-[color:var(--md-on-surface-variant)] transition-transform print:hidden"
          style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
          aria-hidden
        >
          ▾
        </span>
      </button>

      {/* Body is always rendered so it is searchable and prints expanded; hidden
          on screen when collapsed. */}
      <div className={`px-4 pb-4 grid gap-3 ${open ? "" : "hidden print:grid"}`}>
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

        {/* Per-finding actions */}
        <div className="flex flex-wrap items-center gap-2 pt-1 print:hidden">
          <ActionButton onClick={copyLink}>
            {copied === "link" ? "Link copied" : "Copy link"}
          </ActionButton>
          <ActionButton onClick={copyMarkdown}>
            {copied === "md" ? "Markdown copied" : "Copy as Markdown"}
          </ActionButton>
          {/* Manual triage has no per-finding persistence endpoint — surface a
              clearly-disabled control rather than faking it. Bulk LLM triage is
              available from the header's ⋯ menu ("Run LLM triage"). */}
          <span
            className="inline-flex items-center gap-1.5 px-3 h-8 rounded-full md-label-l border border-[color:var(--md-outline-variant)] text-[color:var(--md-on-surface-variant)] opacity-50 cursor-not-allowed"
            title="Manual triage isn't persisted yet. Use “Run LLM triage” from the ⋯ menu."
            aria-disabled="true"
          >
            Triage: {state}
          </span>
        </div>
      </div>
    </article>
  );
}

function ActionButton({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="state-layer inline-flex items-center gap-1.5 px-3 h-8 rounded-full md-label-l border border-[color:var(--md-outline-variant)] text-[color:var(--md-on-surface)] hover:border-[color:var(--md-primary)] transition-colors"
    >
      {children}
    </button>
  );
}

"use client";

/**
 * SummaryTab — the report's landing view. Answers "what should I fix first?"
 * before the reader ever scrolls the raw findings list.
 *
 * Everything here is derived, not stored:
 *   - Top priorities reuse `rankFindings` (the same ROI model the exports use).
 *   - Rollups (by scanner, by OWASP/CWE, by location) are counted on the fly.
 *   - Scan configuration (T2.5) is read from scan.selection / target / meta and
 *     deliberately renders auth *mode* only — never tokens, cookies, passwords.
 *
 * Each top-priority row deep-links into the Findings tab and opens that exact
 * finding (`?tab=findings&sev=all#f-<id>`), which FindingsList expands + scrolls
 * to on mount.
 */

import { useRouter } from "next/navigation";
import { SeverityBadge, Chip } from "../ui/Primitives";
import { rankFindings } from "@/lib/triage/ranker";
import type { Finding, Scan } from "@/lib/types";

/** Auth *mode* only — the concrete secret values must never be surfaced. */
function authMode(scan: Scan): "none" | "manual" | "profile" {
  const auth = scan.target.auth;
  if (!auth) return "none";
  if (auth.profileId) return "profile";
  if (auth.headers || auth.cookies || auth.basicAuth || auth.bearerToken) return "manual";
  return "none";
}

function isAggressive(scan: Scan): boolean {
  const opts = scan.selection.options ?? {};
  const perScanner = Object.values(opts).some(
    (o) => o && typeof o === "object" && (o as Record<string, unknown>).aggressive === true,
  );
  return perScanner || Boolean((scan.meta as Record<string, unknown> | undefined)?.aggressive);
}

function crawlerMaxPages(scan: Scan): number | undefined {
  const c = scan.selection.options?.["web.crawler"]?.maxPages;
  return typeof c === "number" ? c : undefined;
}

function fmtDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function countBy<T>(items: T[], key: (t: T) => string | undefined): [string, number][] {
  const map = new Map<string, number>();
  for (const it of items) {
    const k = key(it);
    if (!k) continue;
    map.set(k, (map.get(k) ?? 0) + 1);
  }
  return [...map.entries()].sort((a, b) => b[1] - a[1]);
}

export function SummaryTab({ scan, findings }: { scan: Scan; findings: Finding[] }) {
  const router = useRouter();
  const running = scan.status === "running" || scan.status === "queued";

  const ranked = rankFindings(findings);
  const top = ranked.slice(0, 5);
  const total = findings.length;
  const actNow = (scan.counts.critical ?? 0) + (scan.counts.high ?? 0);

  const byScanner = countBy(findings, (f) => f.scannerName);
  // OWASP / CWE tags are arrays — flatten before counting.
  const owaspCounts = countBy(
    findings.flatMap((f) => f.owasp ?? []),
    (c) => c,
  );
  const cweCounts = countBy(
    findings.flatMap((f) => f.cwe ?? []),
    (c) => c,
  );
  const byLocation = countBy(findings, (f) => f.location.url ?? f.location.file);

  function openFinding(id: string) {
    // sev=all guarantees the target card is not filtered out before the
    // hash-scroll effect in FindingsList runs.
    router.replace(`?tab=findings&sev=all#f-${id}`, { scroll: false });
  }

  if (total === 0) {
    return (
      <div className="glass-thin p-10 text-center text-[color:var(--md-on-surface-variant)]">
        {running
          ? "Scan in progress — the summary will populate as findings arrive."
          : "No findings for this scan. Nothing to prioritize."}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Posture line */}
      <div className="glass p-4 flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex items-baseline gap-2">
          <span
            className="md-headline-s"
            style={{ fontVariantNumeric: "tabular-nums" }}
          >
            {total}
          </span>
          <span className="md-body-m text-[color:var(--md-on-surface-variant)]">
            {total === 1 ? "finding" : "findings"}
          </span>
        </div>
        <span aria-hidden className="text-[color:var(--md-outline)]">·</span>
        <div className="md-body-m">
          {actNow > 0 ? (
            <span>
              <span
                className="md-title-m"
                style={{ color: "var(--md-severity-high)" }}
              >
                {actNow}
              </span>{" "}
              critical / high need action
            </span>
          ) : (
            <span className="text-[color:var(--md-on-surface-variant)]">
              No critical or high findings — maintain current posture.
            </span>
          )}
        </div>
      </div>

      {/* Top priorities (ROI) */}
      <section className="glass p-4 flex flex-col gap-3">
        <div className="flex items-center justify-between gap-2">
          <h2 className="md-title-m">Fix these first</h2>
          <span className="md-label-s text-[color:var(--md-on-surface-variant)]">
            ranked by ROI
          </span>
        </div>
        <ol className="flex flex-col gap-2">
          {top.map((r) => {
            const f = r.finding;
            const loc = f.location.url ?? f.location.file ?? "";
            return (
              <li key={r.id}>
                <button
                  type="button"
                  onClick={() => openFinding(r.id)}
                  className="state-layer w-full text-left rounded-xl p-3 flex items-start gap-3 border border-[color:var(--md-outline-variant)] hover:border-[color:var(--md-primary)] transition-colors"
                  aria-label={`Priority ${r.rank}: ${f.title}. Open this finding.`}
                >
                  <span
                    className="md-title-m tabular-nums text-[color:var(--md-on-surface-variant)] w-6 shrink-0 text-center"
                    aria-hidden
                  >
                    {r.rank}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="md-title-s break-words min-w-0 flex-1">
                        {f.title}
                      </span>
                    </div>
                    {loc && (
                      <p className="md-body-s mono text-[color:var(--md-on-surface-variant)] mt-1 break-all">
                        {loc}
                      </p>
                    )}
                  </div>
                  <span
                    aria-hidden
                    className="md-label-s text-[color:var(--md-on-surface-variant)] whitespace-nowrap shrink-0 mt-1"
                    title={r.reason}
                  >
                    score {Math.round(r.score)}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      </section>

      {/* Rollups */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <RollupCard title="By scanner" rows={byScanner} />
        <RollupCard
          title={owaspCounts.length > 0 ? "By OWASP" : "By CWE"}
          rows={owaspCounts.length > 0 ? owaspCounts : cweCounts}
          empty="No taxonomy tags on these findings."
          prefix={owaspCounts.length > 0 ? "OWASP " : ""}
        />
        <RollupCard title="Top affected locations" rows={byLocation} mono />
      </div>

      <ScanConfig scan={scan} />
    </div>
  );
}


function RollupCard({
  title,
  rows,
  empty = "None.",
  prefix = "",
  mono = false,
}: {
  title: string;
  rows: [string, number][];
  empty?: string;
  prefix?: string;
  mono?: boolean;
}) {
  const shown = rows.slice(0, 6);
  const rest = rows.length - shown.length;
  return (
    <section className="glass-thin p-4 flex flex-col gap-2">
      <h3 className="md-label-l text-[color:var(--md-on-surface-variant)]">{title}</h3>
      {shown.length === 0 ? (
        <p className="md-body-s text-[color:var(--md-on-surface-variant)]">{empty}</p>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {shown.map(([label, count]) => (
            <li key={label} className="flex items-center gap-2">
              <span
                className={`md-body-s flex-1 min-w-0 truncate ${mono ? "mono" : ""}`}
                title={label}
              >
                {prefix}
                {label}
              </span>
              <span
                className="md-label-s tabular-nums text-[color:var(--md-on-surface-variant)] shrink-0"
                aria-label={`${count} findings`}
              >
                {count}
              </span>
            </li>
          ))}
          {rest > 0 && (
            <li className="md-body-s text-[color:var(--md-on-surface-variant)]">
              +{rest} more
            </li>
          )}
        </ul>
      )}
    </section>
  );
}

function ScanConfig({ scan }: { scan: Scan }) {
  const mode = authMode(scan);
  const maxPages = crawlerMaxPages(scan);
  const aggressive = isAggressive(scan);
  const enabled = scan.selection.enabled ?? [];
  const duration =
    scan.startedAt && scan.finishedAt ? scan.finishedAt - scan.startedAt : undefined;

  const rows: [string, string][] = [
    ["Kind", scan.kind],
    ["Auth mode", mode],
    ["Aggressive", aggressive ? "on" : "off"],
    ...(maxPages !== undefined ? ([["Crawler max pages", String(maxPages)]] as [string, string][]) : []),
    ["Scanners enabled", String(enabled.length)],
    ...(scan.startedAt
      ? ([["Started", new Date(scan.startedAt).toLocaleString()]] as [string, string][])
      : []),
    ...(scan.finishedAt
      ? ([["Finished", new Date(scan.finishedAt).toLocaleString()]] as [string, string][])
      : []),
    ...(duration !== undefined
      ? ([["Duration", fmtDuration(duration)]] as [string, string][])
      : []),
  ];

  return (
    <details className="glass-thin p-4">
      <summary className="md-label-l cursor-pointer flex items-center gap-2">
        <span>Scan configuration</span>
        <span className="md-label-s text-[color:var(--md-on-surface-variant)] font-normal">
          reproducibility · no secrets shown
        </span>
      </summary>
      <div className="mt-3 flex flex-col gap-3">
        <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-2">
          {rows.map(([k, v]) => (
            <div key={k} className="flex flex-col">
              <dt className="md-label-s text-[color:var(--md-on-surface-variant)]">{k}</dt>
              <dd className="md-body-m break-words">{v}</dd>
            </div>
          ))}
        </dl>
        {enabled.length > 0 && (
          <details className="rounded-lg bg-[color-mix(in_oklab,var(--md-on-surface)_3%,transparent)] p-2">
            <summary className="cursor-pointer md-label-s text-[color:var(--md-on-surface-variant)]">
              {enabled.length} scanners
            </summary>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {enabled.map((id) => (
                <Chip key={id} className="!h-6 !px-2 mono">
                  {id}
                </Chip>
              ))}
            </div>
          </details>
        )}
      </div>
    </details>
  );
}

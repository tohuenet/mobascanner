import Link from "next/link";
import { Chip, SeverityBadge, ProgressBar, ScanStatusBadge } from "@/components/ui/Primitives";
import { relativeTime } from "@/components/ui/format";
import { ScannerInventory, type ScannerMeta } from "@/components/dashboard/ScannerInventory";
import { listScans, type ScanIndexEntry } from "@/lib/store";
import { listProjects, listProjectFindings } from "@/lib/projects/store";
import { listScanners } from "@/lib/engine/registry";
import { EMPTY_COUNTS, type Severity } from "@/lib/types";
import "@/lib/scanners";

export const dynamic = "force-dynamic";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function severityTotal(counts: Record<string, number> | undefined): number {
  if (!counts) return 0;
  return SEVERITIES.reduce((a, sev) => a + (counts[sev] ?? 0), 0);
}

/** One posture/summary metric tile. Becomes a link when `href` is provided. */
function Kpi({
  label,
  href,
  className = "",
  children,
}: {
  label: string;
  href?: string;
  className?: string;
  children: React.ReactNode;
}) {
  const base = `glass p-5 flex flex-col gap-1 min-w-0 ${className}`;
  const body = (
    <>
      <span className="md-label-l text-[color:var(--md-on-surface-variant)]">{label}</span>
      {children}
    </>
  );
  return href ? (
    <Link href={href} className={`block state-layer hover:translate-y-[-1px] transition-transform ${base}`}>
      {body}
    </Link>
  ) : (
    <div className={base}>{body}</div>
  );
}

/** A scan row consistent with `/scans` (SeverityBadge, zero counts hidden). */
function ScanRow({ scan, now }: { scan: ScanIndexEntry; now: number }) {
  const total = severityTotal(scan.counts);
  return (
    <Link
      href={`/scans/${scan.id}`}
      className="block glass p-4 state-layer hover:translate-y-[-1px] transition-transform"
    >
      <div className="flex flex-wrap items-center gap-3">
        <Chip className="!h-6 !px-2">{scan.kind}</Chip>
        <ScanStatusBadge status={scan.status} className="!h-6" />
        <span className="md-title-s break-all flex-1 min-w-[200px]">{scan.target}</span>
        <span
          className="md-body-s text-[color:var(--md-on-surface-variant)]"
          title={new Date(scan.createdAt).toLocaleString()}
        >
          {relativeTime(scan.createdAt, now)}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2 mt-2">
        {SEVERITIES.map((sev) =>
          (scan.counts?.[sev] ?? 0) > 0 ? (
            <SeverityBadge key={sev} severity={sev}>
              {sev} · {scan.counts[sev]}
            </SeverityBadge>
          ) : null,
        )}
        <span className="md-body-s text-[color:var(--md-on-surface-variant)] ml-auto">{total} findings</span>
      </div>
    </Link>
  );
}

export default async function Home() {
  // This is a force-dynamic Server Component: it renders once per request on
  // the server, so reading the wall clock is intentional and stable for this
  // render (the purity rule targets client re-renders, which don't apply here).
  // eslint-disable-next-line react-hooks/purity
  const now = Date.now();
  const allScans = await listScans();
  const scanners: ScannerMeta[] = listScanners().map((s) => ({
    id: s.id,
    name: s.name,
    kind: s.kind,
    description: s.description,
  }));

  // ---- All-time posture aggregate (fixes D1: was computed over slice(0, 8)). --
  const totals = allScans.reduce<Record<Severity, number>>(
    (acc, s) => {
      for (const sev of SEVERITIES) acc[sev] += s.counts?.[sev] ?? 0;
      return acc;
    },
    { ...EMPTY_COUNTS },
  );
  const totalFindings = severityTotal(totals);
  const actNow = totals.critical + totals.high;
  const totalScans = allScans.length;
  const distinctTargets = new Set(allScans.map((s) => s.target)).size;
  const active = allScans
    .filter((s) => s.status === "running" || s.status === "queued")
    .sort((a, b) => b.createdAt - a.createdAt);
  const lastScan = allScans.length
    ? allScans.reduce((a, b) => (b.createdAt > a.createdAt ? b : a))
    : null;
  const recent = [...allScans].sort((a, b) => b.createdAt - a.createdAt).slice(0, 6);

  const actNowColor =
    totals.critical > 0
      ? "var(--md-severity-critical)"
      : totals.high > 0
        ? "var(--md-severity-high)"
        : "var(--md-on-surface-variant)";

  // ---- First-run / empty state (T1.5) ---------------------------------------
  if (totalScans === 0) {
    return (
      <div className="grid gap-6">
        <section className="glass-strong p-7 md:p-9 grid gap-5 max-w-3xl">
          <div>
            <span className="md-label-l text-[color:var(--md-on-surface-variant)]">welcome</span>
            <h1 className="md-display-s mt-1">
              Two pentest engines.{" "}
              <span className="brand-gradient-text">One transparent console.</span>
            </h1>
            <p className="md-body-l mt-3 text-[color:var(--md-on-surface-variant)]">
              No scans yet. Kick off your first run — findings stream in live and land in a shareable
              report. Start with a web pentest (DAST) or a source / dependency scan (SAST + SCA).
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link
              href="/scan/web"
              className="state-layer inline-flex items-center gap-2 h-12 px-5 rounded-full bg-[color:var(--md-primary)] text-[color:var(--md-on-primary)] md-label-l shadow-sm"
            >
              <span aria-hidden>🌐</span>
              Start a web pentest
            </Link>
            <Link
              href="/scan/source"
              className="state-layer inline-flex items-center gap-2 h-12 px-5 rounded-full bg-[color:var(--md-secondary-container)] text-[color:var(--md-on-secondary-container)] md-label-l"
            >
              <span aria-hidden>📦</span>
              Scan source code
            </Link>
          </div>
          <div className="glass-thin p-3.5 grid gap-1">
            <p className="md-body-m">
              <span aria-hidden>⚠️ </span>
              <strong>Authorized testing only.</strong> Get written permission before scanning any target
              you don&apos;t own.
            </p>
            <p className="md-body-s text-[color:var(--md-on-surface-variant)]">
              No target handy? Try a public sandbox such as{" "}
              <span className="mono text-[color:var(--md-on-surface)]">http://demo.testfire.net/</span>.
            </p>
          </div>
        </section>

        <ScannerInventory scanners={scanners} />
      </div>
    );
  }

  // ---- Cross-surface correlation (T3) ---------------------------------------
  // The product's wedge: findings both the code (SAST/SCA) and the running app
  // (DAST) agree on. Read each project's correlated findings (small JSONL files;
  // this page is force-dynamic) and count the genuine confirmations.
  const projects = await listProjects();
  const projectStats = await Promise.all(
    projects.map(async (p) => {
      const projectFindings = await listProjectFindings(p.id);
      const confirmed = projectFindings.filter(
        (f) =>
          f.evidence?.crossSurface === true &&
          (f.ruleId === "correlation/cve-cross-surface" ||
            f.ruleId === "correlation/version-reachable"),
      ).length;
      return { id: p.id, name: p.name, confirmed };
    }),
  );
  const totalConfirmed = projectStats.reduce((a, s) => a + s.confirmed, 0);

  // ---- Cockpit (populated) ---------------------------------------------------
  return (
    <div className="grid gap-6">
      {/* In-progress strip (T1.2) — absent entirely when nothing is active. */}
      {active.length > 0 && (
        <section className="grid gap-2" aria-label="Scans in progress">
          <h2 className="md-label-l text-[color:var(--md-on-surface-variant)] uppercase tracking-wide">
            In progress · {active.length}
          </h2>
          {active.map((s) => (
            <Link
              key={s.id}
              href={`/scans/${s.id}`}
              className="block glass p-4 state-layer hover:translate-y-[-1px] transition-transform"
            >
              <div className="flex flex-wrap items-center gap-3">
                <Chip className="!h-6 !px-2">{s.kind}</Chip>
                <span
                  className="inline-flex items-center gap-1.5 md-label-s px-2.5 h-6 rounded-full"
                  style={{
                    color: "var(--md-primary)",
                    background: "color-mix(in oklab, var(--md-primary) 14%, transparent)",
                    border: "1px solid color-mix(in oklab, var(--md-primary) 38%, transparent)",
                  }}
                >
                  <span className="sev-dot" style={{ background: "var(--md-primary)", color: "var(--md-primary)" }} />
                  {s.status}
                </span>
                <span className="md-title-s break-all flex-1 min-w-[200px]">{s.target}</span>
                <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
                  started {relativeTime(s.createdAt, now)}
                </span>
              </div>
              <ProgressBar indeterminate className="mt-3" />
            </Link>
          ))}
        </section>
      )}

      {/* Hero + posture (T1.1) */}
      <section className="glass-strong p-7 md:p-9 grid md:grid-cols-[1fr_auto] gap-6 items-end">
        <div>
          <span className="md-label-l text-[color:var(--md-on-surface-variant)]">overview</span>
          <h1 className="md-display-s mt-1 max-w-2xl">
            Two pentest engines.{" "}
            <span className="brand-gradient-text">One transparent console.</span>
          </h1>
          <p className="md-body-l mt-3 max-w-2xl text-[color:var(--md-on-surface-variant)]">
            Dynamic web scanning plus static source / dependency analysis, normalized and triaged into
            one feed of high-signal findings.
          </p>
          <div className="flex flex-wrap gap-2 mt-5">
            <Link
              href="/scan/web"
              className="state-layer inline-flex items-center gap-2 h-12 px-5 rounded-full bg-[color:var(--md-primary)] text-[color:var(--md-on-primary)] md-label-l shadow-sm"
            >
              <span aria-hidden>🌐</span>
              Start a web pentest
            </Link>
            <Link
              href="/scan/source"
              className="state-layer inline-flex items-center gap-2 h-12 px-5 rounded-full bg-[color:var(--md-secondary-container)] text-[color:var(--md-on-secondary-container)] md-label-l"
            >
              <span aria-hidden>📦</span>
              Scan source code
            </Link>
            <Link
              href="/scans"
              className="state-layer inline-flex items-center gap-2 h-12 px-5 rounded-full border border-[color:var(--md-outline)] md-label-l"
            >
              View past scans
            </Link>
          </div>
        </div>

        {/* Posture panel — the "answer first" number. */}
        <div className="glass p-5 flex flex-col gap-4 min-w-[260px] md:w-[300px]">
          <div className="flex flex-col">
            <span className="md-label-l text-[color:var(--md-on-surface-variant)]">needs attention</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="md-display-m tabular-nums" style={{ color: actNowColor }}>
                {actNow}
              </span>
              <span className="md-body-m text-[color:var(--md-on-surface-variant)]">
                open critical + high
              </span>
            </div>
            {actNow === 0 && (
              <span className="md-body-s text-[color:var(--md-on-surface-variant)] mt-0.5">
                No critical or high findings across all scans.
              </span>
            )}
          </div>
          <div className="flex flex-col gap-1.5">
            <span className="md-label-s text-[color:var(--md-on-surface-variant)] uppercase tracking-wide">
              all-time · by severity
            </span>
            <div className="flex flex-wrap gap-1.5">
              {SEVERITIES.map((sev) => (
                <SeverityBadge key={sev} severity={sev} className={totals[sev] === 0 ? "opacity-45" : ""}>
                  {sev} · {totals[sev]}
                </SeverityBadge>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Secondary KPIs (T1.1) */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3" aria-label="Key metrics">
        <Kpi label="Findings · all-time">
          <span className="md-display-s tabular-nums">{totalFindings}</span>
        </Kpi>
        <Kpi label="Scans" href="/scans">
          <span className="md-display-s tabular-nums">{totalScans}</span>
        </Kpi>
        <Kpi label="Targets">
          <span className="md-display-s tabular-nums">{distinctTargets}</span>
          <span className="md-body-s text-[color:var(--md-on-surface-variant)]">distinct</span>
        </Kpi>
        <Kpi
          label="Last scan"
          href={lastScan ? `/scans/${lastScan.id}` : undefined}
          className="col-span-2 lg:col-span-1"
        >
          {lastScan ? (
            <>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="md-title-l">{relativeTime(lastScan.createdAt, now)}</span>
                <ScanStatusBadge status={lastScan.status} className="!h-6" />
              </div>
              <span className="md-body-s text-[color:var(--md-on-surface-variant)] break-all line-clamp-1">
                {lastScan.target}
              </span>
            </>
          ) : (
            <span className="md-title-l text-[color:var(--md-on-surface-variant)]">—</span>
          )}
        </Kpi>
      </section>

      {/* Cross-surface confirmed (T3) — absent entirely when no projects exist. */}
      {projectStats.length > 0 && (
        <section className="grid gap-3" aria-label="Cross-surface correlation">
          <div className="flex items-center justify-between">
            <h2 className="md-headline-s">Cross-surface confirmed</h2>
            <Link href="/projects" className="md-label-l text-[color:var(--md-primary)] hover:underline">
              View projects →
            </Link>
          </div>
          <div className="glass p-5 grid gap-4 md:grid-cols-[auto_1fr] md:items-center">
            <div className="flex items-baseline gap-2">
              <span
                className="md-display-m tabular-nums"
                style={{ color: totalConfirmed > 0 ? "var(--md-tertiary)" : "var(--md-on-surface-variant)" }}
              >
                {totalConfirmed}
              </span>
              <span className="md-body-m text-[color:var(--md-on-surface-variant)]">
                confirmed cross-surface {totalConfirmed === 1 ? "finding" : "findings"}
              </span>
            </div>
            <div className="flex flex-col gap-2 min-w-0">
              <p className="md-body-s text-[color:var(--md-on-surface-variant)]">
                Findings both the code and the running app agree on, across{" "}
                {projectStats.length} {projectStats.length === 1 ? "project" : "projects"}
                {" — "}the cross-validated exploit paths a DAST-only or source-only tool
                structurally can&apos;t see.
              </p>
              <div className="flex flex-wrap gap-1.5">
                {projectStats.map((p) => (
                  <Link
                    key={p.id}
                    href={`/projects/${p.id}`}
                    className="state-layer inline-flex items-center gap-2 px-3 h-8 rounded-full md-label-l border border-[color:var(--md-outline-variant)] hover:border-[color:var(--md-primary)] transition-colors min-w-0"
                  >
                    <span className="truncate max-w-[200px]">{p.name}</span>
                    <span
                      className="tabular-nums shrink-0"
                      style={{ color: p.confirmed > 0 ? "var(--md-tertiary)" : "var(--md-on-surface-variant)" }}
                      aria-label={`${p.confirmed} confirmed cross-surface`}
                    >
                      {p.confirmed}
                    </span>
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Recent scans (T1.3 / fixes D3) */}
      <section className="grid gap-3">
        <div className="flex items-center justify-between">
          <h2 className="md-headline-s">Recent scans</h2>
          <Link href="/scans" className="md-label-l text-[color:var(--md-primary)] hover:underline">
            View all →
          </Link>
        </div>
        <ul className="grid gap-2">
          {recent.map((s) => (
            <li key={s.id}>
              <ScanRow scan={s} now={now} />
            </li>
          ))}
        </ul>
      </section>

      {/* Scanner inventory (T1.4) */}
      <ScannerInventory scanners={scanners} />
    </div>
  );
}

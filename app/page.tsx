import Link from "next/link";
import { Card, Chip } from "@/components/ui/Primitives";
import { listScans } from "@/lib/store";
import { listScanners } from "@/lib/engine/registry";
import "@/lib/scanners";

export const dynamic = "force-dynamic";

export default async function Home() {
  const scans = (await listScans()).slice(0, 8);
  const scanners = listScanners();

  const totalCounts = scans.reduce(
    (acc, s) => ({
      critical: acc.critical + (s.counts?.critical ?? 0),
      high: acc.high + (s.counts?.high ?? 0),
      medium: acc.medium + (s.counts?.medium ?? 0),
      low: acc.low + (s.counts?.low ?? 0),
      info: acc.info + (s.counts?.info ?? 0),
    }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );

  return (
    <div className="grid gap-6">
      {/* Hero */}
      <section className="glass-strong p-7 md:p-9 grid md:grid-cols-[1fr_auto] gap-6 items-end">
        <div>
          <span className="md-label-l text-[color:var(--md-on-surface-variant)]">welcome</span>
          <h1 className="md-display-s mt-1 max-w-2xl">
            Two pentest engines.{" "}
            <span
              style={{
                background: "linear-gradient(120deg, var(--md-primary), var(--md-tertiary))",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}
            >
              One transparent console.
            </span>
          </h1>
          <p className="md-body-l mt-3 max-w-2xl text-[color:var(--md-on-surface-variant)]">
            Dynamic web scanning (Acunetix-style) plus static source / dependency analysis (SonarQube-style),
            both built on top of best-in-class open-source tooling. We pull, normalize, and triage —
            you get one feed of high-signal findings.
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
        <div className="glass p-4 grid grid-cols-3 sm:grid-cols-5 gap-3 min-w-[260px]">
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
            <div key={s} className="flex flex-col items-center text-center">
              <span
                className="md-display-s"
                style={{ color: `var(--md-severity-${s})` }}
              >
                {totalCounts[s]}
              </span>
              <span className="md-label-s uppercase tracking-wider text-[color:var(--md-on-surface-variant)]">{s}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Recent scans */}
      <section className="grid gap-3">
        <div className="flex items-center justify-between">
          <h2 className="md-headline-s">Recent scans</h2>
          <Link href="/scans" className="md-label-l text-[color:var(--md-primary)] hover:underline">View all →</Link>
        </div>
        {scans.length === 0 ? (
          <Card>
            <p className="md-body-l text-[color:var(--md-on-surface-variant)]">
              No scans yet. Kick off your first one — it&apos;ll show up here in real time.
            </p>
          </Card>
        ) : (
          <ul className="grid gap-2">
            {scans.map((s) => (
              <li key={s.id}>
                <Link href={`/scans/${s.id}`} className="block glass p-4 state-layer hover:translate-y-[-1px] transition-transform">
                  <div className="flex flex-wrap items-center gap-3">
                    <Chip className="!h-6 !px-2">{s.kind}</Chip>
                    <Chip selected={s.status === "completed"} className="!h-6 !px-2">
                      {s.status}
                    </Chip>
                    <span className="md-title-s break-all flex-1 min-w-[200px]">{s.target}</span>
                    <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
                      {new Date(s.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex gap-3 mt-2 text-[color:var(--md-on-surface-variant)] md-body-s">
                    {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
                      <span key={sev}>
                        <span style={{ color: `var(--md-severity-${sev})` }} className="font-semibold">
                          {s.counts?.[sev] ?? 0}
                        </span>{" "}
                        {sev}
                      </span>
                    ))}
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Scanner inventory */}
      <section className="grid gap-3">
        <h2 className="md-headline-s">Scanner inventory</h2>
        <p className="md-body-m text-[color:var(--md-on-surface-variant)] -mt-1">
          Every adapter wraps an upstream open-source project (or runs built-in). Missing CLIs are skipped gracefully.
        </p>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {scanners.map((s) => (
            <Card key={s.id} className="flex flex-col gap-2">
              <div className="flex items-center gap-2">
                <Chip className="!h-6 !px-2">{s.kind}</Chip>
                <h3 className="md-title-m flex-1">{s.name}</h3>
              </div>
              <p className="md-body-s text-[color:var(--md-on-surface-variant)]">{s.description}</p>
              <div className="md-label-s text-[color:var(--md-on-surface-variant)] mono">{s.id}</div>
            </Card>
          ))}
        </div>
      </section>
    </div>
  );
}

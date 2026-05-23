/**
 * Tools inventory — server-rendered health dashboard.
 *
 * In the Docker image every scanner CLI is baked in, so this page should be all
 * green. A red chip means the running server is missing a binary on PATH (e.g.
 * you're running `next dev` on the host outside the image, or you removed a
 * tool). There's no install action — provisioning lives in the Dockerfile.
 */

import { Card, Chip } from "@/components/ui/Primitives";
import { listScanners } from "@/lib/engine/registry";
import "@/lib/scanners";
import type { ToolInfo } from "@/lib/types";

export const dynamic = "force-dynamic";

const STATUS_RANK: Record<ToolInfo["status"], number> = {
  missing: 0,
  unknown: 1,
  outdated: 2,
  available: 3,
};

const STATUS_COLOR: Record<ToolInfo["status"], string> = {
  available: "var(--md-severity-low)",
  missing: "var(--md-severity-high)",
  outdated: "var(--md-severity-medium)",
  unknown: "var(--md-on-surface-variant)",
};

const STATUS_LABEL: Record<ToolInfo["status"], string> = {
  available: "installed",
  missing: "missing",
  outdated: "outdated",
  unknown: "config",
};

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max) + "…";
}

export default async function ToolsPage() {
  const scanners = listScanners();
  // Live detection — runs every scanner's tool() in parallel. ~hundreds of ms
  // inside the image (binaries on PATH); slower if any CLI is missing (8s
  // detectCli timeout per missing tool).
  const tools = await Promise.all(scanners.map((s) => s.tool()));

  const sorted = [...tools].sort((a, b) => {
    if (a.kind !== b.kind) return a.kind.localeCompare(b.kind);
    if (a.status !== b.status) return STATUS_RANK[a.status] - STATUS_RANK[b.status];
    return a.name.localeCompare(b.name);
  });

  const counts = tools.reduce<Record<ToolInfo["status"], number>>(
    (acc, t) => {
      acc[t.status] = (acc[t.status] ?? 0) + 1;
      return acc;
    },
    { available: 0, missing: 0, outdated: 0, unknown: 0 },
  );

  return (
    <div className="grid gap-6">
      <section className="glass-strong p-7 md:p-9">
        <span className="md-label-l text-[color:var(--md-on-surface-variant)]">environment</span>
        <h1 className="md-display-s mt-1">Tools inventory</h1>
        <p className="md-body-l mt-3 max-w-2xl text-[color:var(--md-on-surface-variant)]">
          Every scanner moba-scanner ships with, plus its live status on this server. The official
          Docker image bakes in every CLI — chips here should all be green. A missing chip means
          you&apos;re running outside the image (e.g. <span className="mono">next dev</span> on the
          host) or a binary was removed from <span className="mono">PATH</span>.
        </p>

        <div className="flex flex-wrap gap-2 mt-5">
          <StatusSummary status="available" count={counts.available} />
          <StatusSummary status="missing" count={counts.missing} />
          {counts.outdated > 0 && <StatusSummary status="outdated" count={counts.outdated} />}
          {counts.unknown > 0 && <StatusSummary status="unknown" count={counts.unknown} />}
        </div>

        <p className="md-body-s mt-5 text-[color:var(--md-on-surface-variant)]">
          To run the full stack: <span className="mono">docker compose up --build</span>. To scan
          a service on your host, target <span className="mono">host.docker.internal:&lt;port&gt;</span>.
        </p>
      </section>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {sorted.map((t) => (
          <Card key={t.id} className="flex flex-col gap-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className="sev-dot shrink-0"
                style={{ background: STATUS_COLOR[t.status], color: STATUS_COLOR[t.status] }}
                aria-label={STATUS_LABEL[t.status]}
              />
              <h3 className="md-title-m flex-1 min-w-0 truncate">{t.name}</h3>
              <Chip className="!h-6 !px-2">{t.kind}</Chip>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <span
                className="inline-flex items-center px-2 h-5 rounded-full md-label-s"
                style={{
                  color: STATUS_COLOR[t.status],
                  background: `color-mix(in oklab, ${STATUS_COLOR[t.status]} 16%, transparent)`,
                  border: `1px solid color-mix(in oklab, ${STATUS_COLOR[t.status]} 38%, transparent)`,
                }}
              >
                {STATUS_LABEL[t.status]}
              </span>
              <Chip className="!h-6 !px-2">{t.backend}</Chip>
              {t.detectedVersion && (
                <span className="md-label-s mono text-[color:var(--md-on-surface-variant)]">
                  {truncate(t.detectedVersion, 36)}
                </span>
              )}
              {t.license && (
                <span className="md-label-s text-[color:var(--md-on-surface-variant)]">{t.license}</span>
              )}
            </div>

            <p className="md-body-s text-[color:var(--md-on-surface-variant)]">{t.description}</p>
            <div className="md-label-s mono text-[color:var(--md-on-surface-variant)]">{t.id}</div>

            {t.status === "missing" && t.installHint && (
              <p className="md-body-s text-[color:var(--md-on-surface-variant)]">
                Upstream install: <span className="mono text-[color:var(--md-on-surface)]">{t.installHint}</span>
              </p>
            )}

            {t.upstream && (
              <a
                href={t.upstream}
                target="_blank"
                rel="noopener noreferrer"
                className="md-label-s text-[color:var(--md-primary)] hover:underline mt-auto"
              >
                upstream ↗
              </a>
            )}
          </Card>
        ))}
      </div>
    </div>
  );
}

function StatusSummary({ status, count }: { status: ToolInfo["status"]; count: number }) {
  return (
    <div
      className="inline-flex items-center gap-2 px-3 h-9 rounded-full"
      style={{
        background: `color-mix(in oklab, ${STATUS_COLOR[status]} 14%, transparent)`,
        border: `1px solid color-mix(in oklab, ${STATUS_COLOR[status]} 36%, transparent)`,
        color: STATUS_COLOR[status],
      }}
    >
      <span className="sev-dot" style={{ background: STATUS_COLOR[status], color: STATUS_COLOR[status] }} />
      <span className="md-label-l">{count}</span>
      <span className="md-label-s uppercase tracking-wider">{STATUS_LABEL[status]}</span>
    </div>
  );
}

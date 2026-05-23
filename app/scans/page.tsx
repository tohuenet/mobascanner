import Link from "next/link";
import { Card, Chip, SeverityBadge } from "@/components/ui/Primitives";
import { listScans } from "@/lib/store";

export const dynamic = "force-dynamic";

export default async function ScansListPage() {
  const items = await listScans();
  return (
    <div className="grid gap-5">
      <header className="flex items-baseline justify-between gap-3">
        <div>
          <span className="md-label-l text-[color:var(--md-on-surface-variant)]">history</span>
          <h1 className="md-display-s">All scans</h1>
        </div>
        <div className="flex gap-2">
          <Link
            href="/scan/web"
            className="state-layer inline-flex items-center gap-2 h-10 px-4 rounded-full bg-[color:var(--md-primary)] text-[color:var(--md-on-primary)] md-label-l shadow-sm"
          >
            + Web
          </Link>
          <Link
            href="/scan/source"
            className="state-layer inline-flex items-center gap-2 h-10 px-4 rounded-full bg-[color:var(--md-secondary-container)] text-[color:var(--md-on-secondary-container)] md-label-l"
          >
            + Source
          </Link>
        </div>
      </header>

      {items.length === 0 ? (
        <Card>
          <p className="md-body-l text-[color:var(--md-on-surface-variant)]">
            No scans yet. Start with the buttons above.
          </p>
        </Card>
      ) : (
        <ul className="grid gap-2">
          {items.map((s) => {
            const total = (Object.values(s.counts ?? {}) as number[]).reduce((a, b) => a + b, 0);
            return (
              <li key={s.id}>
                <Link
                  href={`/scans/${s.id}`}
                  className="block glass p-4 state-layer hover:translate-y-[-1px] transition-transform"
                >
                  <div className="flex flex-wrap items-center gap-3">
                    <Chip className="!h-6 !px-2">{s.kind}</Chip>
                    <Chip selected={s.status === "completed"} className="!h-6 !px-2">{s.status}</Chip>
                    <span className="md-title-s break-all flex-1 min-w-[200px]">{s.target}</span>
                    <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
                      {new Date(s.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 mt-2">
                    {(["critical", "high", "medium", "low", "info"] as const).map((sev) =>
                      (s.counts?.[sev] ?? 0) > 0 ? (
                        <SeverityBadge key={sev} severity={sev}>
                          {sev} · {s.counts[sev]}
                        </SeverityBadge>
                      ) : null
                    )}
                    <span className="md-body-s text-[color:var(--md-on-surface-variant)] ml-auto">
                      {total} findings
                    </span>
                  </div>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

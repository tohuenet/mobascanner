"use client";

import { Suspense, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Card, Chip } from "@/components/ui/Primitives";
import { FindingsList } from "@/components/FindingsList";
import type { Finding, Project } from "@/lib/types";
// Type-only import — erased at build time; the store module never bundles.
import type { ScanIndexEntry } from "@/lib/store";

export function ProjectDetail({
  initialProject,
  scans,
  initialFindings,
}: {
  initialProject: Project;
  scans: ScanIndexEntry[];
  initialFindings: Finding[];
}) {
  const router = useRouter();
  const [project, setProject] = useState<Project>(initialProject);
  const [findings, setFindings] = useState<Finding[]>(initialFindings);
  const [attachId, setAttachId] = useState("");
  const [busy, setBusy] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const memberIds = useMemo(() => new Set(project.members.map((m) => m.scanId)), [project]);
  const available = useMemo(
    () => scans.filter((s) => !memberIds.has(s.id)).sort((a, b) => b.createdAt - a.createdAt),
    [scans, memberIds],
  );
  const kinds = useMemo(() => new Set(project.members.map((m) => m.kind)), [project]);
  const crossSurfaceReady = kinds.has("web") && kinds.has("source");

  const attach = async () => {
    if (!attachId || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/projects/${project.id}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId: attachId }),
      });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(j.error ?? "Failed to attach scan.");
        return;
      }
      setProject(j.project);
      setAttachId("");
      router.refresh();
    } finally {
      setBusy(false);
    }
  };

  const detach = async (scanId: string) => {
    setBusy(true);
    try {
      const res = await fetch(`/api/projects/${project.id}/scans?scanId=${encodeURIComponent(scanId)}`, {
        method: "DELETE",
      });
      const j = await res.json().catch(() => ({}));
      if (res.ok) setProject(j.project);
      router.refresh();
    } finally {
      setBusy(false);
    }
  };

  const correlate = async () => {
    setCorrelating(true);
    setError(null);
    setMessage(null);
    try {
      const res = await fetch(`/api/projects/${project.id}/correlate`, { method: "POST" });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(j.error ?? "Correlation failed.");
        return;
      }
      setFindings(j.findings ?? []);
      setMessage(
        j.count === 0
          ? "Correlation ran — no cross-surface matches yet. Attach a web + source scan that share a CVE."
          : `Correlation produced ${j.count} finding${j.count === 1 ? "" : "s"}.`,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCorrelating(false);
    }
  };

  return (
    <div className="grid gap-6">
      <section className="glass-strong p-7 md:p-9">
        <div className="flex flex-wrap items-center gap-3">
          <Link href="/projects" className="md-label-l text-[color:var(--md-primary)] hover:underline">
            ← projects
          </Link>
        </div>
        <h1 className="md-display-s mt-1 break-all">{project.name}</h1>
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <Chip className="!h-7">{project.members.length} member{project.members.length === 1 ? "" : "s"}</Chip>
          {crossSurfaceReady ? (
            <Chip selected className="!h-7">web + source ready</Chip>
          ) : (
            <Chip className="!h-7">
              add {kinds.has("web") ? "a source" : kinds.has("source") ? "a web" : "a web + source"} scan
            </Chip>
          )}
        </div>
      </section>

      {/* Members + attach */}
      <Card className="grid gap-4">
        <h2 className="md-title-m">Members</h2>
        {project.members.length === 0 ? (
          <p className="md-body-m text-[color:var(--md-on-surface-variant)]">
            No scans attached yet.
          </p>
        ) : (
          <ul className="grid gap-2">
            {project.members.map((m) => (
              <li
                key={m.scanId}
                className="glass-thin p-3 flex flex-wrap items-center gap-3"
              >
                <Chip className="!h-6 !px-2">{m.kind}</Chip>
                <Link href={`/scans/${m.scanId}`} className="md-body-m break-all flex-1 min-w-0 hover:underline">
                  {m.target}
                </Link>
                <Button variant="text" size="sm" onClick={() => detach(m.scanId)} disabled={busy}>
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}

        {available.length > 0 && (
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1.5 flex-1 min-w-[240px]">
              <span className="md-label-l text-[color:var(--md-on-surface-variant)]">Attach a scan</span>
              <select
                value={attachId}
                onChange={(e) => setAttachId(e.target.value)}
                className="h-12 px-3 rounded-xl outline-none md-body-l"
                style={{
                  background: "color-mix(in oklab, var(--md-surface-container-low) 80%, transparent)",
                  border: "1px solid var(--md-outline-variant)",
                  color: "var(--md-on-surface)",
                }}
              >
                <option value="">Select a scan…</option>
                {available.map((s) => (
                  <option key={s.id} value={s.id}>
                    [{s.kind}] {s.target}
                  </option>
                ))}
              </select>
            </label>
            <Button variant="tonal" onClick={attach} disabled={!attachId || busy}>
              Attach
            </Button>
          </div>
        )}
      </Card>

      {/* Correlate */}
      <Card className="grid gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="md-title-m">Correlation</h2>
            <p className="md-body-s text-[color:var(--md-on-surface-variant)] mt-1 max-w-xl">
              Joins findings across members on shared CVE ids and runs cross-kind chain rules.
              Re-running is idempotent — it never duplicates.
            </p>
          </div>
          <Button onClick={correlate} disabled={correlating || project.members.length === 0}>
            {correlating ? "Correlating…" : "Correlate"}
          </Button>
        </div>
        {message && <p className="md-body-s text-[color:var(--md-on-surface-variant)]">{message}</p>}
        {error && <p className="md-body-s text-[color:var(--md-error)]">{error}</p>}
      </Card>

      {/* Correlated findings */}
      <div className="grid gap-3">
        <h2 className="md-title-m">
          Correlated findings {findings.length > 0 ? `· ${findings.length}` : ""}
        </h2>
        {findings.length === 0 ? (
          <Card>
            <p className="md-body-m text-[color:var(--md-on-surface-variant)]">
              No correlated findings yet. Attach a web scan and a source scan of the same app, then
              press Correlate.
            </p>
          </Card>
        ) : (
          <>
            <CorrelationSummary findings={findings} />
            <Suspense
              fallback={
                <div className="glass-thin p-6 text-center md-body-s text-[color:var(--md-on-surface-variant)]">
                  Loading findings…
                </div>
              }
            >
              <FindingsList findings={findings} />
            </Suspense>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * The cross-surface categories, in value order — the confirmed/reachable
 * exploit paths (the competitive wedge) lead; the FP-cutting hints trail. Each
 * finding maps to exactly one category via `categorize`.
 */
type CorrCat = "confirmed" | "reachable" | "chain" | "mismatch" | "not-observed";

/** Single, non-overlapping category for a correlated finding (or null). */
function categorize(f: Finding): CorrCat | null {
  const rule = f.ruleId ?? "";
  if (rule === "correlation/version-reachable") return "reachable";
  if (rule === "correlation/version-mismatch") return "mismatch";
  if (rule === "correlation/not-observed-at-runtime") return "not-observed";
  if (rule === "correlation/cve-cross-surface") return "confirmed";
  if (rule.startsWith("chain/") || f.scannerId === "chain") return "chain";
  // Any other cross-surface-tagged synthesis counts as a confirmation.
  if (f.evidence?.crossSurface === true) return "confirmed";
  return null;
}

const CORR_TILES: { cat: CorrCat; label: string; caption: string; color: string }[] = [
  { cat: "confirmed", label: "Confirmed cross-surface", caption: "Code and runtime agree", color: "var(--md-tertiary)" },
  { cat: "reachable", label: "Shipped to production", caption: "Vulnerable build served live", color: "var(--md-severity-critical)" },
  { cat: "chain", label: "Chains", caption: "Multi-step attack paths", color: "var(--md-primary)" },
  { cat: "mismatch", label: "Version mismatch", caption: "Live version differs — verify", color: "var(--md-severity-medium)" },
  { cat: "not-observed", label: "Not observed at runtime", caption: "Likely lower reachability", color: "var(--md-on-surface-variant)" },
];

/**
 * Compact strip that counts the correlated findings by cross-surface category,
 * leading with the highest-value tiles. Zero-count categories are shown but
 * dimmed (never color-alone: each tile carries a count + label + caption).
 */
function CorrelationSummary({ findings }: { findings: Finding[] }) {
  const counts = useMemo(() => {
    const c: Record<CorrCat, number> = {
      confirmed: 0,
      reachable: 0,
      chain: 0,
      mismatch: 0,
      "not-observed": 0,
    };
    for (const f of findings) {
      const cat = categorize(f);
      if (cat) c[cat] += 1;
    }
    return c;
  }, [findings]);

  return (
    <section aria-label="Correlation summary" className="grid gap-2">
      <span className="md-label-l text-[color:var(--md-on-surface-variant)] uppercase tracking-wide">
        Cross-surface correlation
      </span>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
        {CORR_TILES.map((t) => {
          const n = counts[t.cat];
          const zero = n === 0;
          return (
            <div
              key={t.cat}
              className={`glass-thin p-3 flex flex-col gap-0.5 ${zero ? "opacity-45" : ""}`}
              style={{ borderLeft: `3px solid ${zero ? "var(--md-outline-variant)" : t.color}` }}
            >
              <span
                className="md-display-s tabular-nums"
                style={{ color: zero ? "var(--md-on-surface-variant)" : t.color }}
              >
                {n}
              </span>
              <span className="md-label-l">{t.label}</span>
              <span className="md-body-s text-[color:var(--md-on-surface-variant)]">{t.caption}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

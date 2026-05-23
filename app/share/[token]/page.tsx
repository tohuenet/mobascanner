import { notFound } from "next/navigation";
import { getScan, listFindings } from "@/lib/store";
import { verifyShare } from "@/lib/share/jwt";
import { Card, Chip, SeverityBadge } from "@/components/ui/Primitives";

export const dynamic = "force-dynamic";

export default async function SharePage(props: PageProps<"/share/[token]">) {
  const { token } = await props.params;
  let claims;
  try { claims = await verifyShare(token); }
  catch { notFound(); }

  const scan = await getScan(claims.scanId);
  if (!scan) notFound();
  const findings = await listFindings(claims.scanId);
  const visible = claims.scope === "finding"
    ? findings.filter((f) => f.id === claims.findingId)
    : findings;
  if (claims.scope === "finding" && visible.length === 0) notFound();

  return (
    <div className="grid gap-6">
      <header>
        <Chip className="!h-6 !px-2">read-only · share link</Chip>
        <h1 className="md-display-s mt-2 break-all">{scan.target.value}</h1>
        <p className="md-body-l text-[color:var(--md-on-surface-variant)] mt-1">
          {claims.scope === "finding"
            ? `Single finding shared from scan ${scan.id.slice(0, 8)}…`
            : `Full scan report — expires ${new Date(claims.exp * 1000).toLocaleString()}`}
        </p>
      </header>

      <Card glass="glass-strong">
        <div className="grid grid-cols-5 gap-3">
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
            <div key={s} className="flex flex-col items-center text-center">
              <span className="md-headline-m" style={{ color: `var(--md-severity-${s})` }}>
                {claims.scope === "finding"
                  ? (visible[0].severity === s ? 1 : 0)
                  : (scan.counts[s] ?? 0)}
              </span>
              <span className="md-label-s uppercase tracking-wider text-[color:var(--md-on-surface-variant)]">{s}</span>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-3">
        {visible.map((f) => (
          <article key={f.id} className="glass p-4">
            <div className="flex items-start gap-3">
              <SeverityBadge severity={f.severity} />
              <div className="flex-1 min-w-0">
                <h3 className="md-title-m break-words">{f.title}</h3>
                <p className="md-body-s mono text-[color:var(--md-on-surface-variant)] mt-1 break-all">
                  {f.location.url ?? f.location.file ?? ""}
                </p>
                {f.description && <p className="md-body-m mt-2 whitespace-pre-wrap">{f.description}</p>}
                {f.remediation && (
                  <div className="glass-thin p-3 mt-3">
                    <span className="md-label-l">Remediation</span>
                    <p className="md-body-m mt-1 whitespace-pre-wrap">{f.remediation}</p>
                  </div>
                )}
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {f.cwe?.map((c) => <Chip key={c} className="!h-6 !px-2">{c}</Chip>)}
                  {f.cve?.map((c) => <Chip key={c} className="!h-6 !px-2">{c}</Chip>)}
                  {f.owasp?.map((c) => <Chip key={c} className="!h-6 !px-2">OWASP {c}</Chip>)}
                </div>
              </div>
            </div>
          </article>
        ))}
      </div>

      <p className="md-body-s text-[color:var(--md-on-surface-variant)] text-center">
        This link is read-only and expires {new Date(claims.exp * 1000).toLocaleString()}.
      </p>
    </div>
  );
}

import { listScans } from "@/lib/store";
import { listProjects } from "@/lib/projects/store";
import { ProjectsManager } from "@/components/projects/ProjectsManager";

export const dynamic = "force-dynamic";

export default async function ProjectsPage() {
  const [projects, scans] = await Promise.all([listProjects(), listScans()]);
  return (
    <div className="grid gap-6">
      <section className="glass-strong p-7 md:p-9">
        <span className="md-label-l text-[color:var(--md-on-surface-variant)]">correlation</span>
        <h1 className="md-display-s mt-1">Projects</h1>
        <p className="md-body-l mt-3 max-w-2xl text-[color:var(--md-on-surface-variant)]">
          Group a web (DAST) scan of an app with a source (SAST/SCA) scan of its repo. Correlation
          then confirms the findings that appear on <em>both</em> surfaces — the cross-validated
          exploit paths a DAST-only or source-only tool structurally can&apos;t see.
        </p>
      </section>

      <ProjectsManager initialProjects={projects} scans={scans} />
    </div>
  );
}

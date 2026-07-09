import { ToolsManager } from "@/components/ToolsManager";
import { DockerToolbox } from "@/components/DockerToolbox";

export const dynamic = "force-dynamic";

export default function ToolsPage() {
  return (
    <div className="grid gap-6">
      <section className="glass-strong p-7 md:p-9">
        <span className="md-label-l text-[color:var(--md-on-surface-variant)]">environment</span>
        <h1 className="md-display-s mt-1">Tools &amp; installs</h1>
        <p className="md-body-l mt-3 max-w-2xl text-[color:var(--md-on-surface-variant)]">
          Every scanner that wraps an external CLI is listed here with its live status. The fastest way
          to a <strong>complete</strong> scan is the one-click <em>Full toolbox via Docker</em> below —
          it builds an image with every tool baked in. Or install anything still <em>missing</em>
          individually; that command runs <strong>inside the running container</strong>, streams its
          output, and flips the chip when done.
        </p>
        <p className="md-body-s mt-3 max-w-2xl text-[color:var(--md-on-surface-variant)]">
          For safety, one-click actions only run fixed, server-defined commands (never free-form input)
          and are restricted to localhost.
        </p>
      </section>

      <DockerToolbox />

      <ToolsManager />
    </div>
  );
}

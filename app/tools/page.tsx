import { ToolsManager } from "@/components/ToolsManager";

export const dynamic = "force-dynamic";

export default function ToolsPage() {
  return (
    <div className="grid gap-6">
      <section className="glass-strong p-7 md:p-9">
        <span className="md-label-l text-[color:var(--md-on-surface-variant)]">environment</span>
        <h1 className="md-display-s mt-1">Tools &amp; installs</h1>
        <p className="md-body-l mt-3 max-w-2xl text-[color:var(--md-on-surface-variant)]">
          Every scanner that wraps an external CLI is listed here with its live status. The Docker
          image bakes in the full set, so chips should mostly be green. Anything still <em>missing</em>
          can be installed in one click — the command runs <strong>inside the running container</strong>,
          streams its output below, and the chip flips when done. Changes don&apos;t persist across
          <span className="mono"> docker compose down/up</span> — bake them into the Dockerfile if you
          want them permanent.
        </p>
        <p className="md-body-s mt-3 max-w-2xl text-[color:var(--md-on-surface-variant)]">
          For safety, one-click installs only run a fixed, server-defined command per tool (never
          free-form input) and are restricted to localhost.
        </p>
      </section>

      <ToolsManager />
    </div>
  );
}

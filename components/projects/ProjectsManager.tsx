"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Card, Chip, TextField } from "@/components/ui/Primitives";
// Type-only imports — erased at build time, so the server-only store modules
// (which pull in node builtins) never reach the client bundle.
import type { ProjectIndexEntry } from "@/lib/projects/store";
import type { ScanIndexEntry } from "@/lib/store";

export function ProjectsManager({
  initialProjects,
  scans,
}: {
  initialProjects: ProjectIndexEntry[];
  scans: ScanIndexEntry[];
}) {
  const router = useRouter();
  const [projects, setProjects] = useState<ProjectIndexEntry[]>(initialProjects);
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scanLabel = (s: ScanIndexEntry) => `${s.target}`;

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const create = async () => {
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim() }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        setError(j.error ?? "Failed to create project.");
        return;
      }
      const { project } = await res.json();
      // Attach any picked scans to the freshly-created project.
      for (const scanId of selected) {
        await fetch(`/api/projects/${project.id}/scans`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scanId }),
        }).catch(() => {});
      }
      router.push(`/projects/${project.id}`);
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    setProjects((p) => p.filter((x) => x.id !== id));
    await fetch(`/api/projects/${id}`, { method: "DELETE" }).catch(() => {});
    router.refresh();
  };

  const sortedScans = useMemo(
    () => [...scans].sort((a, b) => b.createdAt - a.createdAt),
    [scans],
  );

  return (
    <div className="grid gap-6">
      {/* Create */}
      <Card className="grid gap-4">
        <h2 className="md-title-m">New project</h2>
        <TextField
          label="Project name"
          placeholder="e.g. acme-store (app + repo)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") create();
          }}
        />

        <div className="grid gap-2">
          <span className="md-label-l text-[color:var(--md-on-surface-variant)]">
            Attach scans {selected.size > 0 ? `· ${selected.size} selected` : "(optional)"}
          </span>
          {sortedScans.length === 0 ? (
            <p className="md-body-s text-[color:var(--md-on-surface-variant)]">
              No scans yet — run a web scan and a source scan first, then group them here.
            </p>
          ) : (
            <div
              className="grid gap-1.5 max-h-64 overflow-auto rounded-xl p-2"
              style={{ border: "1px solid var(--md-outline-variant)" }}
            >
              {sortedScans.map((s) => {
                const checked = selected.has(s.id);
                return (
                  <label
                    key={s.id}
                    className="state-layer flex items-center gap-3 rounded-lg px-3 py-2 cursor-pointer"
                    style={{ background: checked ? "color-mix(in oklab, var(--md-primary) 10%, transparent)" : "transparent" }}
                  >
                    <input type="checkbox" checked={checked} onChange={() => toggle(s.id)} />
                    <Chip className="!h-6 !px-2">{s.kind}</Chip>
                    <span className="md-body-m break-all flex-1 min-w-0">{scanLabel(s)}</span>
                    <span className="md-body-s text-[color:var(--md-on-surface-variant)] shrink-0">
                      {s.status}
                    </span>
                  </label>
                );
              })}
            </div>
          )}
        </div>

        {error && <p className="md-body-s text-[color:var(--md-error)]">{error}</p>}

        <div className="flex items-center gap-3">
          <Button onClick={create} disabled={!name.trim() || busy}>
            {busy ? "Creating…" : "Create project"}
          </Button>
          {selected.size > 0 && (
            <Button variant="text" onClick={() => setSelected(new Set())} disabled={busy}>
              Clear selection
            </Button>
          )}
        </div>
      </Card>

      {/* List */}
      {projects.length === 0 ? (
        <Card>
          <p className="md-body-l text-[color:var(--md-on-surface-variant)]">
            No projects yet. Create one above to start correlating.
          </p>
        </Card>
      ) : (
        <ul className="grid gap-2">
          {projects.map((p) => (
            <li key={p.id}>
              <div className="glass p-4 flex flex-wrap items-center gap-3 state-layer">
                <Link href={`/projects/${p.id}`} className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="md-title-s break-all">{p.name}</span>
                    <Chip className="!h-6 !px-2">
                      {p.memberCount} scan{p.memberCount === 1 ? "" : "s"}
                    </Chip>
                  </div>
                  <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
                    {new Date(p.createdAt).toLocaleString()}
                  </span>
                </Link>
                <Button variant="text" size="sm" onClick={() => remove(p.id)}>
                  Delete
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

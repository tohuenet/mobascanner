"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Card, Chip, ToolStatusBadge } from "./ui/Primitives";
import type { ToolInfo } from "@/lib/types";
// Type-only import — erased at build time, so the server-only recipe module
// (which pulls in node builtins) never reaches the client bundle.
import type { InstallPlan } from "@/lib/install/recipes";

type ToolRow = ToolInfo & { defaultEnabled?: boolean };

type InstallEvent =
  | { type: "start"; id: string; label: string; note: string | null; command: string }
  | { type: "log"; stream: "stdout" | "stderr"; line: string }
  | { type: "exit"; code: number; signal: string | null }
  | { type: "status"; status: ToolInfo["status"]; version: string | null }
  | { type: "error"; message: string }
  | { type: "done"; ok: boolean; code?: number };

interface InstallState {
  phase: "running" | "done" | "error";
  command?: string;
  note?: string | null;
  lines: { stream: string; line: string }[];
  ok?: boolean;
}

type Filter = "all" | "installable" | "missing" | "installed";

const FILTERS: { key: Filter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "installable", label: "Can install" },
  { key: "missing", label: "Missing" },
  { key: "installed", label: "Installed" },
];

export function ToolsManager() {
  const [tools, setTools] = useState<ToolRow[]>([]);
  const [plans, setPlans] = useState<Record<string, InstallPlan>>({});
  const [managers, setManagers] = useState<Record<string, boolean>>({});
  const [local, setLocal] = useState(true);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<Filter>("all");
  const [installs, setInstalls] = useState<Record<string, InstallState>>({});
  const [copied, setCopied] = useState<string | null>(null);
  const running = useRef<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [toolsRes, installRes] = await Promise.all([
        fetch("/api/tools").then((r) => r.json()),
        fetch("/api/tools/install").then((r) => r.json()),
      ]);
      setTools((toolsRes.tools as ToolRow[]) ?? []);
      setPlans((installRes.plans as Record<string, InstallPlan>) ?? {});
      setManagers((installRes.managers as Record<string, boolean>) ?? {});
      setLocal(Boolean(installRes.local));
    } catch {
      /* leave previous state */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const copy = (key: string, text: string) => {
    navigator.clipboard?.writeText(text).then(
      () => {
        setCopied(key);
        setTimeout(() => setCopied((c) => (c === key ? null : c)), 1500);
      },
      () => {},
    );
  };

  const chosenCommand = (plan: InstallPlan | undefined): string | null => {
    if (!plan || plan.availableIndex === null) return null;
    const m = plan.methods[plan.availableIndex];
    return `${m.cmd} ${m.args.join(" ")}`;
  };

  const runInstall = async (id: string) => {
    if (running.current.has(id)) return;
    running.current.add(id);
    setInstalls((prev) => ({ ...prev, [id]: { phase: "running", lines: [] } }));

    const apply = (fn: (s: InstallState) => InstallState) =>
      setInstalls((prev) => ({ ...prev, [id]: fn(prev[id] ?? { phase: "running", lines: [] }) }));

    try {
      const res = await fetch("/api/tools/install", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      if (!res.ok || !res.body) {
        const msg = await res.json().catch(() => ({ error: res.statusText }));
        apply((s) => ({
          ...s,
          phase: "error",
          ok: false,
          lines: [...s.lines, { stream: "stderr", line: msg.error ?? "Request failed." }],
        }));
        return;
      }

      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl = buf.indexOf("\n");
        while (nl !== -1) {
          const raw = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          nl = buf.indexOf("\n");
          if (!raw) continue;
          let evt: InstallEvent;
          try {
            evt = JSON.parse(raw) as InstallEvent;
          } catch {
            continue;
          }
          handleEvent(id, evt, apply);
        }
      }
    } catch (e) {
      apply((s) => ({
        ...s,
        phase: "error",
        ok: false,
        lines: [...s.lines, { stream: "stderr", line: e instanceof Error ? e.message : String(e) }],
      }));
    } finally {
      running.current.delete(id);
    }
  };

  const handleEvent = (
    id: string,
    evt: InstallEvent,
    apply: (fn: (s: InstallState) => InstallState) => void,
  ) => {
    switch (evt.type) {
      case "start":
        apply((s) => ({ ...s, command: evt.command, note: evt.note }));
        break;
      case "log":
        apply((s) => ({ ...s, lines: [...s.lines, { stream: evt.stream, line: evt.line }] }));
        break;
      case "exit":
        apply((s) => ({
          ...s,
          lines: [...s.lines, { stream: "meta", line: `— process exited with code ${evt.code}` }],
        }));
        break;
      case "status":
        // Flip the tool's status chip live without a manual refresh.
        setTools((prev) =>
          prev.map((t) =>
            t.id === id ? { ...t, status: evt.status, detectedVersion: evt.version ?? undefined } : t,
          ),
        );
        break;
      case "error":
        apply((s) => ({ ...s, lines: [...s.lines, { stream: "stderr", line: evt.message }] }));
        break;
      case "done":
        apply((s) => ({ ...s, phase: evt.ok ? "done" : "error", ok: evt.ok }));
        break;
    }
  };

  const rank = (t: ToolRow): number => {
    const plan = plans[t.id];
    const installable = !!plan && plan.availableIndex !== null;
    if (t.status === "missing" && installable) return 0; // actionable now
    if (t.status === "missing" && plan) return 1; // recipe but no manager
    if (t.status === "missing") return 2; // manual hint only
    if (t.status === "available") return 4;
    return 3; // unknown / config
  };

  const visible = useMemo(() => {
    const rows = tools.filter((t) => {
      const plan = plans[t.id];
      const installable = !!plan && plan.availableIndex !== null;
      if (filter === "installable") return installable;
      if (filter === "missing") return t.status === "missing";
      if (filter === "installed") return t.status === "available";
      return true;
    });
    return rows.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tools, plans, filter]);

  const counts = useMemo(() => {
    let installable = 0;
    let missing = 0;
    let installed = 0;
    for (const t of tools) {
      const plan = plans[t.id];
      if (!!plan && plan.availableIndex !== null) installable += 1;
      if (t.status === "missing") missing += 1;
      if (t.status === "available") installed += 1;
    }
    return { installable, missing, installed };
  }, [tools, plans]);

  const presentManagers = Object.entries(managers)
    .filter(([, ok]) => ok)
    .map(([cmd]) => cmd);

  if (loading && tools.length === 0) {
    return (
      <div className="grid gap-2">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="glass-thin h-24 animate-pulse" />
        ))}
      </div>
    );
  }

  return (
    <div className="grid gap-4">
      {/* Toolbar */}
      <div className="glass p-4 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => (
            <Chip key={f.key} selected={filter === f.key} onClick={() => setFilter(f.key)} className="!h-8">
              {f.label}
              {f.key === "installable" && counts.installable ? ` · ${counts.installable}` : ""}
              {f.key === "missing" && counts.missing ? ` · ${counts.missing}` : ""}
              {f.key === "installed" && counts.installed ? ` · ${counts.installed}` : ""}
            </Chip>
          ))}
        </div>
        <div className="flex-1" />
        <span className="md-body-s text-[color:var(--md-on-surface-variant)] hidden sm:inline">
          managers:{" "}
          <span className="mono text-[color:var(--md-on-surface)]">
            {presentManagers.length ? presentManagers.join(", ") : "none"}
          </span>
        </span>
        <Button variant="tonal" size="sm" onClick={load} disabled={loading}>
          {loading ? "Refreshing…" : "Re-detect"}
        </Button>
      </div>

      {!local && (
        <Card glass="glass-thin" className="border-l-4" style={{ borderLeftColor: "var(--md-severity-medium)" }}>
          <p className="md-body-m">
            Install buttons are disabled because this page wasn&apos;t opened from{" "}
            <span className="mono">localhost</span>. Open the console at{" "}
            <span className="mono">http://localhost</span> to enable one-click installs.
          </p>
        </Card>
      )}

      {/* Tool list */}
      <div className="grid gap-2">
        {visible.map((t) => {
          const plan = plans[t.id];
          const installable = !!plan && plan.availableIndex !== null && local;
          const cmd = chosenCommand(plan);
          const install = installs[t.id];
          const busy = install?.phase === "running";

          return (
            <div key={t.id} className="glass-thin p-4 flex flex-col gap-3">
              <div className="flex flex-wrap items-start gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="md-title-s">{t.name}</span>
                    <ToolStatusBadge status={t.status} availableLabel="installed" />
                    <Chip className="!h-6 !px-2">{t.kind}</Chip>
                    <Chip className="!h-6 !px-2">{t.backend}</Chip>
                    {t.detectedVersion && (
                      <span className="md-label-s mono text-[color:var(--md-on-surface-variant)]">
                        {t.detectedVersion.length > 44 ? t.detectedVersion.slice(0, 44) + "…" : t.detectedVersion}
                      </span>
                    )}
                    {t.license && (
                      <span className="md-label-s text-[color:var(--md-on-surface-variant)]">{t.license}</span>
                    )}
                  </div>
                  <p className="md-body-s text-[color:var(--md-on-surface-variant)] mt-1">{t.description}</p>
                  <div className="md-label-s mono text-[color:var(--md-on-surface-variant)] mt-1">{t.id}</div>
                </div>

                <div className="flex flex-col items-end gap-2 shrink-0">
                  {installable && cmd && (
                    <Button
                      variant={t.status === "available" ? "outlined" : "filled"}
                      size="sm"
                      onClick={() => runInstall(t.id)}
                      disabled={busy}
                    >
                      {busy
                        ? "Installing…"
                        : t.status === "available"
                          ? "Reinstall"
                          : `Install · ${plan!.methods[plan!.availableIndex!].label}`}
                    </Button>
                  )}
                  {t.upstream && (
                    <a
                      href={t.upstream}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="md-label-s text-[color:var(--md-primary)] hover:underline"
                    >
                      upstream ↗
                    </a>
                  )}
                </div>
              </div>

              {/* The exact command we'll run — transparency for an exec endpoint. */}
              {installable && cmd && (
                <CommandRow
                  command={cmd}
                  copied={copied === `cmd:${t.id}`}
                  onCopy={() => copy(`cmd:${t.id}`, cmd)}
                />
              )}

              {/* Recipe exists but no package manager is present. */}
              {plan && plan.availableIndex === null && (
                <div className="grid gap-1.5">
                  <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
                    No supported package manager found. Install one of these, then re-detect:
                  </span>
                  {plan.methods.map((m, i) => {
                    const c = `${m.cmd} ${m.args.join(" ")}`;
                    return (
                      <CommandRow
                        key={i}
                        command={c}
                        label={m.label}
                        copied={copied === `m:${t.id}:${i}`}
                        onCopy={() => copy(`m:${t.id}:${i}`, c)}
                      />
                    );
                  })}
                </div>
              )}

              {/* No recipe (API key / daemon / manual download) — show the hint. */}
              {!plan && t.status !== "available" && t.installHint && (
                <CommandRow
                  command={t.installHint}
                  label="manual"
                  copied={copied === `hint:${t.id}`}
                  onCopy={() => copy(`hint:${t.id}`, t.installHint!)}
                />
              )}

              {/* Live install log. */}
              {install && (
                <div className="grid gap-1">
                  <div className="flex items-center gap-2">
                    <span className="md-label-s text-[color:var(--md-on-surface-variant)]">install log</span>
                    {install.phase === "done" && (
                      <span className="md-label-s" style={{ color: "var(--md-severity-low)" }}>
                        {install.ok ? "✓ finished" : "finished with errors"}
                      </span>
                    )}
                    {install.phase === "error" && (
                      <span className="md-label-s" style={{ color: "var(--md-error)" }}>
                        ✗ failed
                      </span>
                    )}
                    {install.phase === "running" && (
                      <span className="md-label-s" style={{ color: "var(--md-primary)" }}>
                        running…
                      </span>
                    )}
                  </div>
                  <pre
                    ref={(el) => {
                      if (el) el.scrollTop = el.scrollHeight;
                    }}
                    className="mono md-body-s rounded-xl p-3 overflow-auto max-h-64 whitespace-pre-wrap break-words"
                    style={{
                      background: "var(--md-surface-container-lowest)",
                      border: "1px solid var(--md-outline-variant)",
                      color: "var(--md-on-surface)",
                    }}
                  >
                    {install.command ? `$ ${install.command}\n` : ""}
                    {install.note ? `# ${install.note}\n` : ""}
                    {install.lines.map((l, i) => (
                      <span
                        key={i}
                        style={{
                          color:
                            l.stream === "stderr"
                              ? "var(--md-error)"
                              : l.stream === "meta"
                                ? "var(--md-on-surface-variant)"
                                : "inherit",
                        }}
                      >
                        {l.line}
                        {"\n"}
                      </span>
                    ))}
                    {install.phase === "running" && install.lines.length === 0 ? "…\n" : ""}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {visible.length === 0 && (
        <Card>
          <p className="md-body-m text-[color:var(--md-on-surface-variant)]">No tools match this filter.</p>
        </Card>
      )}
    </div>
  );
}

function CommandRow({
  command,
  label,
  copied,
  onCopy,
}: {
  command: string;
  label?: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div
      className="flex items-center gap-2 rounded-xl px-3 py-2"
      style={{ background: "var(--md-surface-container-low)", border: "1px solid var(--md-outline-variant)" }}
    >
      {label && <span className="md-label-s text-[color:var(--md-on-surface-variant)] shrink-0">{label}</span>}
      <code className="mono md-body-s flex-1 min-w-0 truncate text-[color:var(--md-on-surface)]">{command}</code>
      <button
        onClick={onCopy}
        className="state-layer shrink-0 rounded-lg px-2 h-7 md-label-s border border-[color:var(--md-outline-variant)] text-[color:var(--md-on-surface-variant)]"
      >
        {copied ? "copied" : "copy"}
      </button>
    </div>
  );
}

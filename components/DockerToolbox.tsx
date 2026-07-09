"use client";

/**
 * DockerToolbox — one-click "full toolbox". The Docker image bakes in every
 * external scanner CLI, so building & launching it turns a partial host scan
 * (only the few tools that happen to be installed) into a comprehensive one.
 *
 * Streams `docker compose up --build -d` output live, then links to the running
 * full-toolbox instance. Localhost-guarded server-side.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Card } from "./ui/Primitives";
import type { ToolInfo } from "@/lib/types";

interface DockerStatus {
  local: boolean;
  inDocker: boolean;
  docker: { available: boolean; version: string | null; compose: boolean; daemon: boolean };
  image: { built: boolean };
  container: { running: boolean; ports: string | null };
  defaultHostPort: number;
  command: string;
}

type Evt =
  | { type: "start"; action: string; hostPort: number; command: string }
  | { type: "log"; stream: "stdout" | "stderr"; line: string }
  | { type: "exit"; code: number; signal: string | null }
  | { type: "ready"; url: string; hostPort: number }
  | { type: "error"; message: string }
  | { type: "done"; ok: boolean; code?: number };

export function DockerToolbox() {
  const [status, setStatus] = useState<DockerStatus | null>(null);
  const [missingCli, setMissingCli] = useState<number | null>(null);
  const [totalCli, setTotalCli] = useState<number | null>(null);
  const [phase, setPhase] = useState<"idle" | "running" | "done" | "error">("idle");
  const [lines, setLines] = useState<{ stream: string; line: string }[]>([]);
  const [readyUrl, setReadyUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const busy = useRef(false);

  const load = useCallback(async () => {
    try {
      const [d, t] = await Promise.all([
        fetch("/api/tools/docker").then((r) => r.json()),
        fetch("/api/tools").then((r) => r.json()),
      ]);
      setStatus(d as DockerStatus);
      const tools = (t.tools as ToolInfo[]) ?? [];
      const ext = tools.filter((x) => x.backend === "cli" || x.backend === "api");
      setTotalCli(ext.length);
      setMissingCli(ext.filter((x) => x.status !== "available").length);
    } catch { /* leave nulls */ }
  }, []);

  useEffect(() => { load(); }, [load]);

  const run = async (action: "up" | "down") => {
    if (busy.current) return;
    busy.current = true;
    setPhase("running");
    setLines([]);
    setReadyUrl(null);
    try {
      const res = await fetch("/api/tools/docker", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, hostPort: status?.defaultHostPort }),
      });
      if (!res.ok || !res.body) {
        const j = await res.json().catch(() => ({ error: res.statusText }));
        setLines((l) => [...l, { stream: "stderr", line: j.error ?? "Request failed." }]);
        setPhase("error");
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
          let evt: Evt;
          try { evt = JSON.parse(raw) as Evt; } catch { continue; }
          if (evt.type === "start") setLines((l) => [...l, { stream: "meta", line: `$ ${evt.command}` }]);
          else if (evt.type === "log") setLines((l) => [...l, { stream: evt.stream, line: evt.line }]);
          else if (evt.type === "exit") setLines((l) => [...l, { stream: "meta", line: `— docker exited ${evt.code}` }]);
          else if (evt.type === "error") setLines((l) => [...l, { stream: "stderr", line: evt.message }]);
          else if (evt.type === "ready") setReadyUrl(evt.url);
          else if (evt.type === "done") setPhase(evt.ok ? "done" : "error");
        }
      }
    } catch (e) {
      setLines((l) => [...l, { stream: "stderr", line: e instanceof Error ? e.message : String(e) }]);
      setPhase("error");
    } finally {
      busy.current = false;
      void load();
    }
  };

  const copyCmd = () => {
    const cmd = status?.command ?? "docker compose up --build -d";
    navigator.clipboard?.writeText(cmd).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }, () => {});
  };

  // Already the full image → nothing to do.
  if (status?.inDocker) {
    return (
      <Card glass="glass-thin" className="border-l-4" style={{ borderLeftColor: "var(--md-severity-low)" }}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="md-title-s">✓ Full-toolbox image</span>
          <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
            You&apos;re running inside the Docker image — every wrapped CLI is on PATH, so scans are comprehensive.
          </span>
        </div>
      </Card>
    );
  }

  const daemonDown = !!status?.docker.available && !!status?.docker.compose && !status?.docker.daemon;
  const canRun = !!status?.docker.available && !!status?.docker.compose && !!status?.docker.daemon && status?.local;
  const gap = missingCli ?? 0;

  return (
    <Card glass="glass-strong" className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start gap-3">
        <div className="flex-1 min-w-0">
          <h2 className="md-title-l">Full toolbox via Docker</h2>
          <p className="md-body-m text-[color:var(--md-on-surface-variant)] mt-1 max-w-2xl">
            The Docker image bakes in <strong>every</strong> external scanner (nuclei, nmap, sqlmap,
            semgrep, trivy, subfinder, and ~25 more). Build &amp; launch it once to scan comprehensively
            instead of being limited to whatever&apos;s installed on this host.
          </p>
          {missingCli !== null && totalCli !== null && (
            <p className="md-body-s mt-2" style={{ color: gap > 0 ? "var(--md-severity-medium)" : "var(--md-severity-low)" }}>
              {gap > 0
                ? `⚠ ${gap} of ${totalCli} external tools are missing here — the Docker instance has all of them.`
                : `All ${totalCli} external tools are present on this host.`}
            </p>
          )}
        </div>
      </div>

      {/* Status line */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 md-body-s text-[color:var(--md-on-surface-variant)]">
        <span>Docker: <b style={{ color: status?.docker.available ? "var(--md-severity-low)" : "var(--md-error)" }}>{status ? (status.docker.available ? (status.docker.version ?? "installed") : "not found") : "…"}</b></span>
        {status?.docker.available && <span>Engine: <b style={{ color: status.docker.daemon ? "var(--md-severity-low)" : "var(--md-severity-medium)" }}>{status.docker.daemon ? "running" : "stopped"}</b></span>}
        {status?.docker.available && <span>Compose: <b>{status.docker.compose ? "yes" : "no"}</b></span>}
        {status?.docker.daemon && <span>Image built: <b>{status.image.built ? "yes" : "no"}</b></span>}
        {status?.container.running && <span style={{ color: "var(--md-severity-low)" }}>● running{status.container.ports ? ` (${status.container.ports})` : ""}</span>}
      </div>

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-2">
        {canRun ? (
          <>
            <Button variant="filled" size="lg" onClick={() => run("up")} disabled={phase === "running"}>
              {phase === "running" ? "Building & launching…" : status?.image.built ? `Rebuild & launch (port ${status.defaultHostPort})` : `Build & launch full toolbox (port ${status?.defaultHostPort})`}
            </Button>
            {status?.container.running && (
              <Button variant="outlined" size="lg" onClick={() => run("down")} disabled={phase === "running"}>
                Stop instance
              </Button>
            )}
          </>
        ) : (
          <div className="flex flex-col gap-1">
            <span className="md-body-s" style={{ color: "var(--md-severity-medium)" }}>
              {status && !status.local
                ? "One-click launch is localhost-only. Open the console at http://localhost."
                : daemonDown
                  ? "Docker is installed but the engine isn't running. Start Docker Desktop, then Re-check — or run:"
                  : "Docker (with the Compose plugin) isn't available here. Install Docker Desktop, then run:"}
            </span>
            <div className="flex items-center gap-2 rounded-xl px-3 py-2" style={{ background: "var(--md-surface-container-low)", border: "1px solid var(--md-outline-variant)" }}>
              <code className="mono md-body-s flex-1 min-w-0 truncate">{status?.command ?? "docker compose up --build -d"}</code>
              <button onClick={copyCmd} className="state-layer shrink-0 rounded-lg px-2 h-7 md-label-s border border-[color:var(--md-outline-variant)]">{copied ? "copied" : "copy"}</button>
            </div>
          </div>
        )}
        <span className="flex-1" />
        <Button variant="text" size="sm" onClick={() => void load()}>Re-check</Button>
      </div>

      {(readyUrl || status?.container.running) && (
        <div className="rounded-xl p-3 flex flex-wrap items-center gap-2" style={{ background: "color-mix(in oklab, var(--md-severity-low) 12%, transparent)", border: "1px solid color-mix(in oklab, var(--md-severity-low) 40%, transparent)" }}>
          <span className="md-body-m">✓ Full-toolbox instance is up.</span>
          <a href={readyUrl ?? `http://localhost:${status?.defaultHostPort}`} target="_blank" rel="noopener noreferrer" className="md-label-l" style={{ color: "var(--md-primary)" }}>
            Open it ↗ ({readyUrl ?? `http://localhost:${status?.defaultHostPort}`})
          </a>
          <span className="md-body-s text-[color:var(--md-on-surface-variant)] w-full">
            The healthcheck may take ~30–60s after a fresh build. Run your comprehensive scans there.
          </span>
        </div>
      )}

      {/* Live build/run log */}
      {lines.length > 0 && (
        <div className="grid gap-1">
          <div className="flex items-center gap-2">
            <span className="md-label-s text-[color:var(--md-on-surface-variant)]">docker log</span>
            {phase === "running" && <span className="md-label-s" style={{ color: "var(--md-primary)" }}>running… (first build downloads GBs — can take 10–20 min)</span>}
            {phase === "done" && <span className="md-label-s" style={{ color: "var(--md-severity-low)" }}>✓ finished</span>}
            {phase === "error" && <span className="md-label-s" style={{ color: "var(--md-error)" }}>✗ failed</span>}
          </div>
          <pre
            ref={(el) => { if (el) el.scrollTop = el.scrollHeight; }}
            className="mono md-body-s rounded-xl p-3 overflow-auto max-h-72 whitespace-pre-wrap break-words"
            style={{ background: "var(--md-surface-container-lowest)", border: "1px solid var(--md-outline-variant)", color: "var(--md-on-surface)" }}
          >
            {lines.map((l, i) => (
              <span key={i} style={{ color: l.stream === "stderr" ? "var(--md-error)" : l.stream === "meta" ? "var(--md-on-surface-variant)" : "inherit" }}>
                {l.line}{"\n"}
              </span>
            ))}
          </pre>
        </div>
      )}
    </Card>
  );
}

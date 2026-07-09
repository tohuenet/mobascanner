"use client";

/**
 * ScanHeader — top-of-page header for the scan-detail view.
 *
 * Layout intent: target URL gets visual weight (it's WHAT was scanned); status
 * chip + elapsed + total findings sit as a muted summary line below; secondary
 * actions (triage, exports, delete) live in a single "More" overflow menu so
 * they don't compete with results for attention.
 */

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Button, Chip, ScanStatusBadge } from "./ui/Primitives";
import { useToast } from "./ui/Toast";
import type { Scan } from "@/lib/types";

function formatElapsed(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return `${m}m ${rs}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function ScanHeader({
  scan,
  totalFindings,
  nowMs,
}: {
  scan: Scan;
  totalFindings: number;
  /** Caller passes a periodic tick so elapsed updates while running. */
  nowMs: number;
}) {
  const elapsed = scan.startedAt ? (scan.finishedAt ?? nowMs) - scan.startedAt : 0;

  return (
    <header className="flex flex-col gap-3">
      <Link
        href="/scans"
        className="md-label-l text-[color:var(--md-primary)] hover:underline w-fit print:hidden"
      >
        ← all scans
      </Link>

      <div className="flex flex-wrap items-start gap-3">
        <h1 className="md-headline-m flex-1 min-w-[200px] break-all">
          {scan.target.value}
        </h1>
        <MoreMenu scanId={scan.id} status={scan.status} />
      </div>

      <div className="flex flex-wrap items-center gap-2 md-body-s text-[color:var(--md-on-surface-variant)]">
        <Chip className="!h-7">{scan.kind}</Chip>
        <ScanStatusBadge status={scan.status} className="!h-7" />
        <span aria-hidden>·</span>
        <span>{formatElapsed(elapsed)}</span>
        <span aria-hidden>·</span>
        <span>
          {totalFindings} {totalFindings === 1 ? "finding" : "findings"}
        </span>
        {scan.startedAt && (
          <>
            <span aria-hidden>·</span>
            <span>started {new Date(scan.startedAt).toLocaleString()}</span>
          </>
        )}
      </div>
    </header>
  );
}

function MoreMenu({ scanId, status }: { scanId: string; status: Scan["status"] }) {
  const router = useRouter();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onMouse = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onMouse);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onMouse);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  async function runTriage() {
    setBusy("triage");
    try {
      const r = await fetch(`/api/scans/${scanId}/triage`, { method: "POST" });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      toast(`Triage done: ${j.decisions?.length ?? 0} decision(s). Reload to see them.`, { tone: "success" });
    } catch (e) {
      toast(`Triage failed: ${e instanceof Error ? e.message : String(e)}`, { tone: "error" });
    } finally {
      setBusy(null);
      setOpen(false);
    }
  }

  async function copyShareUrl() {
    try {
      await navigator.clipboard.writeText(window.location.href);
      toast("URL copied to clipboard", { tone: "success" });
    } catch {
      toast("Failed to copy URL", { tone: "error" });
    }
    setOpen(false);
  }

  async function cancelRun() {
    if (!confirm("Stop this running scan? Already-collected findings stay.")) return;
    setBusy("cancel");
    try {
      const r = await fetch(`/api/scans/${scanId}/cancel`, { method: "POST" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      toast(j.cancelled ? "Cancel sent — scan should stop shortly" : "Scan already finished");
    } catch (e) {
      toast(`Cancel failed: ${e instanceof Error ? e.message : String(e)}`, { tone: "error" });
    } finally {
      setBusy(null);
      setOpen(false);
    }
  }

  async function deleteScan() {
    if (!confirm("Delete this scan and all its artifacts? This cannot be undone.")) return;
    setBusy("delete");
    try {
      const r = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      router.push("/scans");
    } catch (e) {
      toast(`Delete failed: ${e instanceof Error ? e.message : String(e)}`, { tone: "error" });
      setBusy(null);
      setOpen(false);
    }
  }

  return (
    <div ref={ref} className="relative print:hidden">
      <Button
        variant="outlined"
        size="sm"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        ⋯ More
      </Button>

      {open && (
        <div
          role="menu"
          aria-label="Scan actions"
          className="glass-strong absolute right-0 top-full mt-2 min-w-[240px] z-20 flex flex-col p-1"
        >
          {(status === "running" || status === "queued") && (
            <>
              <MenuItem onSelect={cancelRun} disabled={busy === "cancel"} danger>
                {busy === "cancel" ? "Cancelling…" : "Stop scan"}
              </MenuItem>
              <MenuDivider />
            </>
          )}
          <MenuItem
            onSelect={runTriage}
            disabled={busy === "triage" || status !== "completed"}
            hint={status !== "completed" ? "available after scan completes" : undefined}
          >
            {busy === "triage" ? "Triaging…" : "Run LLM triage"}
          </MenuItem>
          <MenuDivider />
          <MenuItem href={`/api/scans/${scanId}/report?format=html`} download>
            Export HTML report
          </MenuItem>
          <MenuItem href={`/api/scans/${scanId}/report?format=markdown`} download>
            Export Markdown report
          </MenuItem>
          <MenuItem href={`/api/scans/${scanId}/report?format=exec-summary`} download>
            Export exec summary (Markdown)
          </MenuItem>
          <MenuItem href={`/api/scans/${scanId}/sarif`} download>
            Export SARIF
          </MenuItem>
          <MenuItem onSelect={copyShareUrl}>Copy URL</MenuItem>
          <MenuDivider />
          <MenuItem onSelect={deleteScan} disabled={busy === "delete"} danger>
            {busy === "delete" ? "Deleting…" : "Delete scan"}
          </MenuItem>
        </div>
      )}
    </div>
  );
}

function MenuItem({
  children,
  onSelect,
  href,
  download,
  disabled,
  danger,
  hint,
}: {
  children: React.ReactNode;
  onSelect?: () => void | Promise<void>;
  href?: string;
  download?: boolean;
  disabled?: boolean;
  danger?: boolean;
  hint?: string;
}) {
  const base =
    "state-layer text-left px-3 py-2 rounded-lg md-label-l flex flex-col gap-0.5 disabled:opacity-50 disabled:pointer-events-none";
  const tone = danger ? "text-[color:var(--md-error)]" : "text-[color:var(--md-on-surface)]";
  if (href) {
    return (
      <a
        role="menuitem"
        href={href}
        download={download}
        className={`${base} ${tone}`}
      >
        <span>{children}</span>
      </a>
    );
  }
  return (
    <button
      type="button"
      role="menuitem"
      onClick={onSelect}
      disabled={disabled}
      className={`${base} ${tone}`}
    >
      <span>{children}</span>
      {hint && (
        <span className="md-body-s text-[color:var(--md-on-surface-variant)]">{hint}</span>
      )}
    </button>
  );
}

function MenuDivider() {
  return (
    <div
      aria-hidden
      className="h-px my-1 mx-2"
      style={{ background: "color-mix(in oklab, var(--md-on-surface) 12%, transparent)" }}
    />
  );
}

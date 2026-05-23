"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, TextField, Card, Chip } from "@/components/ui/Primitives";
import { ScannerSelector, type ScannerSelectorState } from "@/components/ScannerSelector";

type Mode = "git" | "local";

export default function SourceScanPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("git");
  const [target, setTarget] = useState("https://github.com/");
  const [ref, setRef] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selector, setSelector] = useState<ScannerSelectorState>({ enabled: {} });

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          kind: "source",
          target: {
            value: target,
            type: mode,
            ...(ref ? { ref } : {}),
          },
          selection: {
            enabled: Object.entries(selector.enabled).filter(([, v]) => v).map(([k]) => k),
          },
        }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error ?? `HTTP ${res.status}`);
      }
      const { id } = await res.json();
      router.push(`/scans/${id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setSubmitting(false);
    }
  }

  return (
    <div className="grid gap-6">
      <header className="flex flex-col gap-2">
        <span className="md-label-l text-[color:var(--md-on-surface-variant)]">new scan</span>
        <h1 className="md-display-s">Source pentest</h1>
        <p className="md-body-l text-[color:var(--md-on-surface-variant)] max-w-2xl">
          Pull source from a git URL or scan a local checkout — secrets, CVEs in deps, IaC misconfigs,
          static analysis findings, all merged into one feed.
        </p>
      </header>

      <form onSubmit={onSubmit} className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <Card glass="glass-strong" className="flex flex-col gap-5">
          <div>
            <label className="md-label-l text-[color:var(--md-on-surface-variant)]">Source</label>
            <div className="flex gap-2 mt-1.5">
              <Chip selected={mode === "git"} onClick={() => { setMode("git"); setTarget("https://github.com/"); }}>git URL</Chip>
              <Chip selected={mode === "local"} onClick={() => { setMode("local"); setTarget(""); }}>local path</Chip>
            </div>
          </div>

          {mode === "git" ? (
            <>
              <TextField
                label="Git repository URL"
                placeholder="https://github.com/owner/repo.git"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                hint="Public repos only. Private repos require a token configured server-side."
                autoComplete="off"
                required
              />
              <TextField
                label="Branch / tag (optional)"
                placeholder="main"
                value={ref}
                onChange={(e) => setRef(e.target.value)}
              />
            </>
          ) : (
            <TextField
              label="Local directory path"
              placeholder="C:\\projects\\my-app  or  /home/me/code/my-app"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              hint="Path is relative to the moba-scanner server, not the browser."
              autoComplete="off"
              required
            />
          )}

          <div className="flex flex-wrap gap-2 items-center">
            <Button type="submit" disabled={submitting || target.length < 2} variant="filled" size="lg">
              {submitting ? "Starting…" : "Start scan"}
            </Button>
            {error && <span className="md-body-s text-[color:var(--md-error)]">{error}</span>}
          </div>
        </Card>

        <aside className="grid gap-3">
          <h2 className="md-title-l">Scanners</h2>
          <ScannerSelector kind="source" state={selector} onChange={setSelector} />
        </aside>
      </form>

      <Card>
        <h3 className="md-title-l">Coverage at a glance</h3>
        <div className="flex flex-wrap gap-1.5 mt-2">
          {[
            "Secret patterns (AWS, GitHub, Stripe, JWT, private keys)",
            "Semgrep — OWASP rules, language taint analysis",
            "Trivy — CVE deps, IaC misconfigs, license issues",
            "Gitleaks — git-history secret sweep",
          ].map((label) => <Chip key={label}>{label}</Chip>)}
        </div>
      </Card>
    </div>
  );
}

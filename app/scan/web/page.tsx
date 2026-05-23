"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, TextField, Card, Chip } from "@/components/ui/Primitives";
import { ScannerSelector, type ScannerSelectorState } from "@/components/ScannerSelector";
import { AuthPicker, type AuthValue } from "@/components/auth/AuthPicker";

function parseHeaders(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of s.split("\n")) {
    const i = line.indexOf(":");
    if (i < 0) continue;
    const k = line.slice(0, i).trim();
    const v = line.slice(i + 1).trim();
    if (k && v) out[k] = v;
  }
  return out;
}

/** Build the auth fragment sent to /api/scans based on the chosen mode. */
function buildAuthPayload(auth: AuthValue): Record<string, unknown> | undefined {
  if (auth.mode === "none") return undefined;
  if (auth.mode === "manual") {
    const headers = parseHeaders(auth.headers ?? "");
    const out: Record<string, unknown> = {};
    if (Object.keys(headers).length > 0) out.headers = headers;
    if (auth.bearer?.trim()) out.bearerToken = auth.bearer.trim();
    return Object.keys(out).length ? out : undefined;
  }
  // profile mode
  if (!auth.profileId) return undefined;
  return { profileId: auth.profileId };
}

export default function WebScanPage() {
  const router = useRouter();
  const [target, setTarget] = useState("https://");
  const [auth, setAuth] = useState<AuthValue>({ mode: "none" });
  const [maxPages, setMaxPages] = useState(25);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selector, setSelector] = useState<ScannerSelectorState>({ enabled: {} });

  // Profile mode is only really useful with a picked profile — block submit
  // until one exists, otherwise the scan would silently run unauthenticated.
  const profileModeIncomplete = auth.mode === "profile" && !auth.profileId;
  const canSubmit = target.startsWith("http") && !submitting && !profileModeIncomplete;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const authPayload = buildAuthPayload(auth);
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          kind: "web",
          target: {
            value: target,
            type: "url",
            ...(authPayload ? { auth: authPayload } : {}),
          },
          selection: {
            enabled: Object.entries(selector.enabled)
              .filter(([, v]) => v)
              .map(([k]) => k),
            options: { "web.crawler": { maxPages } },
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
        <h1 className="md-display-s">Web pentest</h1>
        <p className="md-body-l text-[color:var(--md-on-surface-variant)] max-w-2xl">
          Crawl a live target, inspect TLS / cookies / headers, and run nuclei templates against it.
          Bot crawls in parallel — share the seed URL with whatever browser you&apos;re also driving.
        </p>
      </header>

      <form onSubmit={onSubmit} className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <Card glass="glass-strong" className="flex flex-col gap-5">
          <TextField
            label="Target URL"
            placeholder="https://target.example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            hint="Must be an absolute URL. Make sure you have written permission to test this host."
            autoComplete="off"
            required
          />

          <AuthPicker value={auth} onChange={setAuth} targetUrl={target} />

          <TextField
            label="Crawler — max pages"
            type="number"
            value={maxPages}
            onChange={(e) => setMaxPages(Number(e.target.value) || 25)}
          />

          <div className="flex flex-wrap gap-2 items-center">
            <Button type="submit" disabled={!canSubmit} variant="filled" size="lg">
              {submitting ? "Starting…" : "Start scan"}
            </Button>
            {profileModeIncomplete && (
              <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
                Pick or capture a profile to start an authenticated scan.
              </span>
            )}
            {error && <span className="md-body-s text-[color:var(--md-error)]">{error}</span>}
          </div>
        </Card>

        <aside className="grid gap-3">
          <h2 className="md-title-l">Scanners</h2>
          <ScannerSelector kind="web" state={selector} onChange={setSelector} />
        </aside>
      </form>

      <Card>
        <h3 className="md-title-l">Coverage at a glance</h3>
        <div className="flex flex-wrap gap-1.5 mt-2">
          {[
            "Security headers (HSTS, CSP, X-Frame-Options, COOP, …)",
            "Cookie posture (Secure, HttpOnly, SameSite)",
            "TLS handshake & certificate chain",
            "HTML crawler (mixed content, insecure forms, tabnabbing)",
            "Nuclei templates (CVEs, exposures, misconfigs)",
          ].map((label) => (
            <Chip key={label}>{label}</Chip>
          ))}
        </div>
      </Card>
    </div>
  );
}

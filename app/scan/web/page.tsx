"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, TextField, Card, Chip, Switch } from "@/components/ui/Primitives";
import { ScannerSelector, type ScannerSelectorState } from "@/components/ScannerSelector";
import { AuthPicker, type AuthValue } from "@/components/auth/AuthPicker";

/** Scanner ids that read scan.options[id].aggressive. Kept in one place so a
 *  single UI toggle fans out across every scanner that honors it. */
const AGGRESSIVE_SCANNERS = ["web.form-fuzzer", "web.spa-crawler", "web.query-fuzzer"] as const;

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

interface PreflightFailure {
  error: string;
  status?: number;
  durationMs: number;
}

export default function WebScanPage() {
  const router = useRouter();
  const [target, setTarget] = useState("https://");
  const [auth, setAuth] = useState<AuthValue>({ mode: "none" });
  const [maxPages, setMaxPages] = useState(25);
  const [aggressive, setAggressive] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selector, setSelector] = useState<ScannerSelectorState>({ enabled: {} });
  // When the seed URL doesn't respond, we block submit and offer "scan anyway".
  const [preflightFail, setPreflightFail] = useState<PreflightFailure | null>(null);

  // Profile mode is only really useful with a picked profile — block submit
  // until one exists, otherwise the scan would silently run unauthenticated.
  const profileModeIncomplete = auth.mode === "profile" && !auth.profileId;
  const canSubmit = target.startsWith("http") && !submitting && !profileModeIncomplete;

  /** Performs the actual /api/scans POST. Split out so "Scan anyway" can reuse it. */
  async function submitScan() {
    setError(null);
    setPreflightFail(null);
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
            options: {
              "web.crawler": { maxPages },
              // Fan the single Aggressive toggle out across every scanner
              // that honors it (form-fuzzer skips its login-form filter,
              // spa-crawler / query-fuzzer pick it up similarly).
              ...(aggressive
                ? Object.fromEntries(AGGRESSIVE_SCANNERS.map((id) => [id, { aggressive: true }]))
                : {}),
            },
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

  /** Form handler: pre-flight reachability, then submit (or surface failure). */
  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setPreflightFail(null);
    setError(null);
    setSubmitting(true);
    try {
      const pf = await fetch("/api/preflight", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: target }),
      })
        .then((r) => r.json())
        .catch((err) => ({ reachable: false, error: err?.message ?? "preflight failed", durationMs: 0 }));
      if (!pf.reachable) {
        setSubmitting(false);
        setPreflightFail({
          error: pf.error ?? "no response",
          status: pf.status,
          durationMs: pf.durationMs ?? 0,
        });
        return;
      }
    } catch {
      // If preflight itself blows up unexpectedly, fall through to submit so
      // we don't gate the user on a broken probe.
    }
    await submitScan();
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

          {/* One-click demo target. Works when juice-shop sidecar is up via
              `docker compose --profile demo up`; otherwise the preflight check
              below will catch the unreachable host. */}
          <div className="flex flex-wrap gap-2 items-center -mt-2">
            <span className="md-label-s text-[color:var(--md-on-surface-variant)]">Quick targets:</span>
            <button
              type="button"
              onClick={() => setTarget("http://juice-shop:3000/")}
              className="state-layer rounded-full px-3 h-7 md-label-s border border-[color:var(--md-outline-variant)] text-[color:var(--md-on-surface)]"
            >
              OWASP Juice Shop (local)
            </button>
            <button
              type="button"
              onClick={() => setTarget("http://demo.testfire.net/")}
              className="state-layer rounded-full px-3 h-7 md-label-s border border-[color:var(--md-outline-variant)] text-[color:var(--md-on-surface)]"
            >
              demo.testfire.net (public)
            </button>
          </div>

          <AuthPicker value={auth} onChange={setAuth} targetUrl={target} />

          <TextField
            label="Crawler — max pages"
            type="number"
            value={maxPages}
            onChange={(e) => setMaxPages(Number(e.target.value) || 25)}
          />

          <div
            className="rounded-xl p-3 flex flex-col gap-2"
            style={{
              background: aggressive
                ? "color-mix(in oklab, var(--md-error) 8%, transparent)"
                : "color-mix(in oklab, var(--md-on-surface) 3%, transparent)",
              border: `1px solid ${aggressive ? "color-mix(in oklab, var(--md-error) 35%, transparent)" : "color-mix(in oklab, var(--md-outline) 50%, transparent)"}`,
            }}
          >
            <Switch
              checked={aggressive}
              onChange={setAggressive}
              label="Aggressive mode"
              hint="Fuzz login forms too, no destructive keyword blocklist. Only enable on throwaway / staging targets."
            />
            {aggressive && (
              <span className="md-body-s" style={{ color: "var(--md-error)" }}>
                ⚠ active submitters will hit every form — including destructive
                actions like delete/logout/transfer.
              </span>
            )}
          </div>

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

          {/* Preflight failure: target didn't respond. Block submit + offer override. */}
          {preflightFail && (
            <div
              className="rounded-xl p-3 flex flex-col gap-2"
              style={{
                background: "color-mix(in oklab, var(--md-error) 8%, transparent)",
                border: "1px solid color-mix(in oklab, var(--md-error) 38%, transparent)",
              }}
            >
              <span className="md-body-m" style={{ color: "var(--md-error)" }}>
                ⚠ Target didn&apos;t respond ({preflightFail.durationMs}ms): {preflightFail.error}
              </span>
              <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
                Running scanners now would burn time and return empty results. Fix the URL,
                bring the host up, or scan anyway if you know the seed path is unusual.
              </span>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outlined"
                  size="sm"
                  onClick={() => {
                    setPreflightFail(null);
                    void submitScan();
                  }}
                >
                  Scan anyway
                </Button>
                <Button
                  type="button"
                  variant="text"
                  size="sm"
                  onClick={() => setPreflightFail(null)}
                >
                  Dismiss
                </Button>
              </div>
            </div>
          )}
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

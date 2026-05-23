/**
 * Domain types shared by engine, scanners, API, and UI.
 *
 * Design notes:
 * - Findings are normalized — every adapter MUST emit `Finding` objects, never
 *   raw tool output. The triage layer can then filter/dedupe/prioritize uniformly.
 * - `Scan` carries a `kind` (web | source) so the same UI path can render either.
 * - Severity uses CVSS v3 buckets plus an "info" tier for low-signal findings.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ScanKind = "web" | "source";

export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type ToolStatus = "available" | "missing" | "outdated" | "unknown";

/**
 * A normalized vulnerability / weakness finding.
 * One scanner run typically produces N Finding records.
 */
export interface Finding {
  id: string;
  scanId: string;
  scannerId: string;        // e.g. "web.headers", "source.semgrep"
  scannerName: string;      // human label
  severity: Severity;
  confidence: "high" | "medium" | "low";
  title: string;
  description: string;
  /** Rule / template id from the upstream tool, if any. */
  ruleId?: string;
  /** External taxonomy (CWE / OWASP / CVE) — optional. */
  cwe?: string[];
  cve?: string[];
  owasp?: string[];
  cvss?: number;            // CVSS base score (0..10)
  /** For web findings: URL evidence. For source findings: file:line. */
  location: {
    url?: string;
    file?: string;
    line?: number;
    column?: number;
    endLine?: number;
    snippet?: string;
  };
  /** Raw evidence — request/response pair, matched code block, payload, etc. */
  evidence?: Record<string, unknown>;
  /** Remediation advice (markdown allowed). */
  remediation?: string;
  references?: string[];
  /** Triage decision (set by user or LLM). */
  triage?: {
    state: "open" | "false-positive" | "fixed" | "accepted-risk";
    note?: string;
    by?: string;
    at?: number;
  };
  createdAt: number;
}

export interface ScanTarget {
  /** For web: an absolute URL. For source: a git URL or local path or upload id. */
  value: string;
  /** Hint for the engine — derived from kind + value. */
  type: "url" | "git" | "local" | "archive";
  /** Auth/headers/cookies for web. */
  auth?: {
    headers?: Record<string, string>;
    cookies?: Record<string, string>;
    basicAuth?: { username: string; password: string };
    bearerToken?: string;
    /** Reference to a captured login profile in the vault. Resolved to a
     *  cookie header server-side at scan creation; persisted on the scan so
     *  the original source is auditable. */
    profileId?: string;
  };
  /** Branch / ref for git source scans. */
  ref?: string;
}

export interface ScannerSelection {
  /** Scanner ids that should run for this scan. */
  enabled: string[];
  /** Scanner-specific options. */
  options?: Record<string, Record<string, unknown>>;
}

export interface ScanProgress {
  scannerId: string;
  state: "pending" | "running" | "completed" | "failed" | "skipped";
  message?: string;
  /** 0..1 if known. */
  progress?: number;
  startedAt?: number;
  finishedAt?: number;
  findingCount?: number;
  errorMessage?: string;
}

export interface Scan {
  id: string;
  kind: ScanKind;
  target: ScanTarget;
  selection: ScannerSelection;
  status: ScanStatus;
  createdAt: number;
  startedAt?: number;
  finishedAt?: number;
  /** Per-scanner progress. */
  progress: Record<string, ScanProgress>;
  /** Aggregated counts kept in-sync as findings stream in. */
  counts: Record<Severity, number>;
  /** Free-form metadata: user agent, repo info, etc. */
  meta?: Record<string, unknown>;
  errorMessage?: string;
}

export interface ToolInfo {
  id: string;                  // matches scanner id
  name: string;                // human label
  kind: ScanKind;
  /** What backs this scanner. */
  backend: "builtin" | "cli" | "api" | "library";
  /** If `cli`, the executable name we look for. */
  cliCommand?: string;
  cliVersionArg?: string;
  /** If `api`, the source repo we'd clone. */
  repoUrl?: string;
  /** Detected at runtime. */
  status: ToolStatus;
  detectedVersion?: string;
  installHint?: string;
  /** Open-source project we wrap (URL). */
  upstream?: string;
  /** License hint of upstream tool. */
  license?: string;
  /** Description shown in UI. */
  description: string;
}

/**
 * SSE event payloads streamed to the UI during a scan.
 * `kind` is the discriminator — keep types narrow so the client can switch on it.
 */
export type ScanEvent =
  | { kind: "scan-started"; scanId: string; at: number }
  | { kind: "scanner-started"; scanId: string; scannerId: string; at: number }
  | { kind: "scanner-progress"; scanId: string; scannerId: string; progress: number; message?: string }
  | { kind: "scanner-finished"; scanId: string; scannerId: string; findings: number; at: number }
  | { kind: "scanner-failed"; scanId: string; scannerId: string; error: string; at: number }
  | { kind: "finding"; scanId: string; finding: Finding }
  | { kind: "scan-finished"; scanId: string; at: number; counts: Record<Severity, number> }
  | { kind: "scan-failed"; scanId: string; error: string; at: number }
  | { kind: "log"; scanId: string; level: "info" | "warn" | "error"; message: string; at: number }
  | {
      kind: "discovered";
      scanId: string;
      /** Use a structurally-typed payload here instead of importing the
       *  DiscoveredItem union to avoid a types↔engine import cycle. */
      item: {
        kind: "url" | "form" | "endpoint";
        url?: string;
        method?: string;
        source: { scannerId: string; via: string; parentUrl?: string };
      };
      at: number;
    };

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const EMPTY_COUNTS: Record<Severity, number> = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

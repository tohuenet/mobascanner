/**
 * Scanner adapter contract.
 *
 * Every integration — built-in or external CLI — implements this. Engine
 * doesn't care whether it's wrapping nuclei, semgrep, or pure JS regex.
 *
 * Adapters yield findings via the provided emit callback so the runner can
 * stream them out as they arrive (instead of buffering until completion).
 */

import type { Finding, ScanKind, ScanTarget, ToolInfo } from "../types";
import type { DiscoveredItem } from "./discovery";

export type { DiscoveredItem };

export interface ScanContext {
  scanId: string;
  target: ScanTarget;
  /** Scanner-specific options coming from `ScannerSelection.options[id]`. */
  options: Record<string, unknown>;
  /** Stream a finding to the bus + persistence as soon as it's discovered. */
  emit: (finding: Omit<Finding, "id" | "scanId" | "scannerId" | "scannerName" | "createdAt">) => Promise<void>;
  /** Free-form log line surfaced to the UI. */
  log: (level: "info" | "warn" | "error", message: string) => Promise<void>;
  /** 0..1 progress hint. */
  progress: (fraction: number, message?: string) => Promise<void>;
  /** AbortSignal so long-running adapters can bail out on cancel. */
  signal: AbortSignal;
  /** Publish a URL / form / endpoint into the per-scan DiscoveryBus. Returns
   *  true iff the item was new AND survived page-class clustering — i.e. a
   *  subscriber will see it. Optional to call; legacy scanners that don't
   *  publish anything still work. */
  discover: (item: DiscoveredItem) => boolean;
}

export interface Scanner {
  /** Stable identifier — must be unique. Convention: "<kind>.<tool>" */
  id: string;
  /** Human label shown in UI. */
  name: string;
  /** What kind of scans this is valid for. */
  kind: ScanKind;
  /** Show in selector. */
  description: string;
  /** Default-on. */
  defaultEnabled?: boolean;
  /** Tool metadata for the /api/tools endpoint. */
  tool: () => Promise<ToolInfo>;
  /** Actual scan implementation. */
  run(ctx: ScanContext): Promise<void>;
  /** Scanner ids this one needs to complete first. The runner uses this to
   *  build a dependency graph and run independent scanners concurrently.
   *  Default: [] — except web scanners that read the SiteMap, which depend on
   *  "web.crawler". The runner auto-injects that dependency for any web
   *  scanner that doesn't declare an explicit list. */
  dependsOn?: string[];
  /** If false, this scanner is heavy and should be serialized rather than
   *  parallelized with others (e.g. nuclei full template run). Default: true. */
  parallelSafe?: boolean;
  /** Optional: declare this scanner as a "consumer" of dynamically-discovered
   *  items. The runner subscribes it to the DiscoveryBus AFTER the static
   *  scanner waves complete, replays the current snapshot, and waits for the
   *  bus to drain before finishing the scan. Scanners without `consume` run
   *  in the static-wave phase only (the legacy model). */
  consume?: (item: DiscoveredItem, ctx: ScanContext) => Promise<void>;
  /** Limit which discovery kinds this consumer cares about. Default: all. */
  consumes?: Array<DiscoveredItem["kind"]>;
}

/** Helper: build a Finding draft with sensible defaults. */
export function draft(
  partial: Partial<Omit<Finding, "id" | "scanId" | "scannerId" | "scannerName" | "createdAt">>,
): Omit<Finding, "id" | "scanId" | "scannerId" | "scannerName" | "createdAt"> {
  return {
    severity: partial.severity ?? "info",
    confidence: partial.confidence ?? "medium",
    title: partial.title ?? "Untitled finding",
    description: partial.description ?? "",
    ruleId: partial.ruleId,
    cwe: partial.cwe,
    cve: partial.cve,
    owasp: partial.owasp,
    cvss: partial.cvss,
    location: partial.location ?? {},
    evidence: partial.evidence,
    remediation: partial.remediation,
    references: partial.references,
    triage: partial.triage,
  };
}

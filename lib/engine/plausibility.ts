/**
 * Post-scan plausibility self-audit.
 *
 * The primary defense against false positives is the per-scanner differential
 * oracle (`lib/scanners/web/_oracle.ts`), which measures noise, rejects
 * blocked/empty probes, runs a negative control, and RE-CONFIRMS before
 * emitting. This module is the cheap, non-destructive backstop: after a scan it
 * looks for the statistical signature of a false-positive FLOOD — one scanner
 * emitting an implausible burst of high/critical findings — and surfaces a
 * warning so a regression is visible instead of silently trusted.
 *
 * It deliberately does NOT delete or demote findings. Suppressing real
 * criticals is worse than a warning; the corrective logic belongs at the
 * source (the oracle), and rule/location de-duplication is handled separately
 * by `dedup.ts`. This layer only reports.
 */

import type { Finding, Severity } from "../types";

const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

/** A scanner is "flooding" if it emits at least this many high/critical
 *  findings — above the count a genuinely vulnerable target usually yields from
 *  a single detector. Tuned to catch the 19-critical / 109-high signatures
 *  while staying clear of realistic clusters. */
const HIGH_SEV_BURST = 12;

export interface PlausibilityWarning {
  scannerId: string;
  severity: "critical" | "high";
  count: number;
  message: string;
}

/**
 * Inspect a finished scan's findings for implausible high-severity bursts.
 * Returns zero or more warnings; callers log them. Pure and side-effect-free.
 */
export function auditFindings(findings: Finding[]): PlausibilityWarning[] {
  const warnings: PlausibilityWarning[] = [];
  // Bucket high/critical findings by (scannerId, severity).
  const buckets = new Map<string, Finding[]>();
  for (const f of findings) {
    if (SEVERITY_RANK[f.severity] < SEVERITY_RANK.high) continue;
    const key = `${f.scannerId}|${f.severity}`;
    (buckets.get(key) ?? buckets.set(key, []).get(key)!).push(f);
  }
  for (const [key, list] of buckets) {
    if (list.length < HIGH_SEV_BURST) continue;
    const [scannerId, severity] = key.split("|") as [string, "critical" | "high"];
    const pages = new Set(list.map((f) => f.location?.url ?? "")).size;
    warnings.push({
      scannerId,
      severity,
      count: list.length,
      message: `${scannerId} emitted ${list.length} ${severity} findings across ${pages} location(s) — implausibly many for one detector. Review for false positives before trusting them; a healthy detector rarely produces this many ${severity}s on one target.`,
    });
  }
  return warnings;
}

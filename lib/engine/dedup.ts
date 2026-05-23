/**
 * Finding deduplication post-process.
 *
 * Many scanners catch overlapping issues:
 *   - active-injection + form-fuzzer both find the same XSS sink
 *   - content-discovery + nuclei both flag /.env reachable
 *   - subdomain-enum + nuclei both report the same forgotten host
 *   - param-miner + active-injection both report the same reflective param
 *
 * Without dedup, the UI fills with near-duplicates and triage is painful.
 * This module canonicalizes findings into "buckets" using:
 *
 *   bucket-key = severity-bucket + ruleClass + canonical-location
 *
 * where:
 *   - ruleClass groups variants ("xss/reflected" + "xss/reflected-form" + "reflection/json-echo" → "xss")
 *   - canonical-location strips the query value but keeps the param name
 *
 * Findings that fall into the same bucket are merged: the one with the
 * highest (severity, confidence) wins, and the others are recorded under
 * `evidence.duplicates[]` so we never silently lose context.
 */

import type { Finding, Severity } from "../types";

const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const CONFIDENCE_RANK = { high: 3, medium: 2, low: 1 } as const;

/** Strip `?key=value` → `?key=`. Keeps the parameter set, drops noisy values. */
function canonicalUrl(u?: string): string {
  if (!u) return "";
  try {
    const url = new URL(u);
    const keys = [...url.searchParams.keys()].sort();
    return `${url.origin}${url.pathname}${keys.length ? "?" + keys.map((k) => `${k}=`).join("&") : ""}`;
  } catch {
    return u;
  }
}

/**
 * Map a noisy ruleId to a stable "rule class". E.g. all XSS variants collapse
 * to "xss"; all SQLi variants to "sqli"; etc. Unknown rules pass through.
 */
function ruleClass(ruleId?: string, scannerId?: string): string {
  const id = (ruleId ?? scannerId ?? "").toLowerCase();
  if (/xss|reflection\/json/.test(id)) return "xss";
  if (/sqli/.test(id)) return "sqli";
  if (/lfi|traversal/.test(id)) return "lfi";
  if (/cmdi|cmd-injection/.test(id)) return "cmdi";
  if (/ssrf/.test(id)) return "ssrf";
  if (/open-redirect/.test(id)) return "open-redirect";
  if (/headers\//.test(id)) return id.split("?")[0]; // keep header-name distinct
  if (/cookies\//.test(id)) return id.split("?")[0];
  if (/cors\//.test(id)) return "cors";
  if (/jwt\//.test(id)) return id.split("?")[0]; // alg-none, no-exp distinct
  if (/idor/.test(id)) return "idor";
  if (/verb-tampering/.test(id)) return "verb-tampering";
  if (/content-discovery/.test(id)) return id.split("?")[0]; // path is part of the rule
  if (/nuclei/.test(id)) return id; // each template is its own rule
  return id || "unknown";
}

function canonicalLocation(f: Finding): string {
  if (f.location.file) return `${f.location.file}:${f.location.line ?? ""}`;
  return canonicalUrl(f.location.url);
}

function preferredOf(a: Finding, b: Finding): Finding {
  const ar = SEVERITY_RANK[a.severity] * 10 + CONFIDENCE_RANK[a.confidence];
  const br = SEVERITY_RANK[b.severity] * 10 + CONFIDENCE_RANK[b.confidence];
  return ar >= br ? a : b;
}

export interface DedupResult {
  kept: Finding[];
  removed: Finding[];
  /** How many duplicates were collapsed in total. */
  collapsedCount: number;
}

export function dedupFindings(findings: Finding[]): DedupResult {
  const buckets = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = `${ruleClass(f.ruleId, f.scannerId)}::${canonicalLocation(f)}`;
    const list = buckets.get(key);
    if (list) list.push(f);
    else buckets.set(key, [f]);
  }
  const kept: Finding[] = [];
  const removed: Finding[] = [];
  let collapsed = 0;
  for (const list of buckets.values()) {
    if (list.length === 1) { kept.push(list[0]); continue; }
    let primary = list[0];
    for (let i = 1; i < list.length; i++) primary = preferredOf(primary, list[i]);
    const others = list.filter((x) => x.id !== primary.id);
    primary = {
      ...primary,
      evidence: {
        ...(primary.evidence ?? {}),
        duplicates: others.map((o) => ({
          scanner: o.scannerName,
          ruleId: o.ruleId,
          severity: o.severity,
          confidence: o.confidence,
          title: o.title,
        })),
        duplicateCount: others.length,
        seenByScanners: [primary.scannerName, ...others.map((o) => o.scannerName)].filter((v, i, a) => a.indexOf(v) === i),
      },
    };
    kept.push(primary);
    removed.push(...others);
    collapsed += others.length;
  }
  return { kept, removed, collapsedCount: collapsed };
}

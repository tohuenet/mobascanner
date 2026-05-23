/**
 * Heuristic ranker — score every finding by a simple ROI formula:
 *
 *   score = severity_weight × confidence_weight × exploitability × asset_value
 *
 * exploitability is derived from:
 *   - rule class (active probe confirmed > passive observation)
 *   - chain detection presence
 *   - whether OOB callback fired (if interactsh ran)
 *
 * asset_value bumps for findings on auth-relevant URLs (/login, /admin,
 * /api/me, /payment, /transfer) and downgrades for static-shaped paths.
 *
 * The output is a ranked Finding[] — the UI renders the top 10 in a
 * "fix this week" panel.
 */

import type { Finding } from "../types";

const SEV_WEIGHT: Record<string, number> = { critical: 100, high: 60, medium: 25, low: 8, info: 1 };
const CONF_WEIGHT: Record<string, number> = { high: 1.0, medium: 0.7, low: 0.4 };

const HIGH_VALUE_RE = /\/(login|signin|admin|administrator|payment|pay|checkout|transfer|withdraw|wallet|api\/me|me|account|user|users|wp-admin|console)\b/i;
const LOW_VALUE_RE  = /\.(css|woff2?|ttf|eot|svg|ico|png|jpe?g|gif|map)(\?|$)/i;

const ACTIVE_RULES = /^(sqli|xss|lfi|cmdi|ssrf|ssti|nosql|xxe|proto-pollution|cve|brute-login|jwt\/alg-none|jwt\/empty-sig|verb-tampering|idor|crlf|host-header|race-condition|graphql\/(?:bola|batching|depth)|oob)/;
const PASSIVE_RULES = /^(headers|cookies|cors|fingerprint|sri|hsts|dns|email|api-key-in-url|content-discovery|deserialization)/;

interface RankedFinding {
  id: string;
  rank: number;
  score: number;
  reason: string;
  finding: Finding;
}

export function rankFindings(findings: Finding[]): RankedFinding[] {
  const scored: RankedFinding[] = findings.map((f) => {
    const sev = SEV_WEIGHT[f.severity] ?? 1;
    const conf = CONF_WEIGHT[f.confidence] ?? 0.7;
    let exploitability = 0.7;
    const rule = (f.ruleId ?? f.scannerId ?? "").toLowerCase();
    if (ACTIVE_RULES.test(rule)) exploitability = 1.0;
    if (PASSIVE_RULES.test(rule)) exploitability = 0.4;
    if (f.scannerId === "chain") exploitability = 1.2; // composite is a real exploit narrative
    if (rule.startsWith("oob/")) exploitability = 1.3; // OOB callback confirmed

    let asset = 1.0;
    const urlOrFile = f.location.url ?? f.location.file ?? "";
    if (HIGH_VALUE_RE.test(urlOrFile)) asset = 1.5;
    if (LOW_VALUE_RE.test(urlOrFile)) asset = 0.5;

    const score = sev * conf * exploitability * asset;
    const reason = [
      `sev ${f.severity} (×${sev})`,
      `conf ${f.confidence} (×${conf.toFixed(1)})`,
      `expl ${exploitability.toFixed(1)}`,
      asset !== 1.0 ? `asset ×${asset}` : null,
    ].filter(Boolean).join(" · ");
    return { id: f.id, rank: 0, score, reason, finding: f };
  });
  scored.sort((a, b) => b.score - a.score);
  scored.forEach((s, i) => { s.rank = i + 1; });
  return scored;
}

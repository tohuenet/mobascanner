/**
 * GET /api/scans/[id]/diff/[other] — compare two scans of (presumably) the
 * same target. Returns:
 *
 *   {
 *     added:    Finding[]    // present in 'id' but not in 'other'
 *     removed:  Finding[]    // present in 'other' but not in 'id'
 *     persistent: number     // count of findings present in both
 *   }
 *
 * Identity is by canonical (rule-class, location). Useful for:
 *   - PR-diff scanning: scan PR build vs main, surface only NEW findings
 *   - regression detection: scheduled scan vs last week's
 *   - QA sign-off: post-fix verification
 */

import { NextResponse } from "next/server";
import { listFindings } from "@/lib/store";
import type { Finding } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function canonicalKey(f: Finding): string {
  const cls = (() => {
    const id = (f.ruleId ?? f.scannerId ?? "").toLowerCase();
    if (/xss/.test(id)) return "xss";
    if (/sqli/.test(id)) return "sqli";
    if (/lfi|traversal/.test(id)) return "lfi";
    if (/cmdi/.test(id)) return "cmdi";
    if (/ssrf/.test(id)) return "ssrf";
    if (/headers\//.test(id)) return id;
    if (/cookies\//.test(id)) return id;
    if (/cors\//.test(id)) return "cors";
    if (/jwt\//.test(id)) return id;
    return id || "unknown";
  })();
  const loc = f.location.file
    ? `${f.location.file}:${f.location.line ?? ""}`
    : (() => { try { const u = new URL(f.location.url ?? ""); return `${u.origin}${u.pathname}`; } catch { return f.location.url ?? ""; } })();
  return `${cls}::${loc}`;
}

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/diff/[other]">) {
  const { id, other } = await ctx.params;
  if (id === other) return NextResponse.json({ error: "scans must differ" }, { status: 400 });

  const [a, b] = await Promise.all([listFindings(id), listFindings(other)]);
  const aKeys = new Map(a.map((f) => [canonicalKey(f), f]));
  const bKeys = new Map(b.map((f) => [canonicalKey(f), f]));

  const added: Finding[] = [];
  const removed: Finding[] = [];
  let persistent = 0;
  for (const [k, f] of aKeys) (bKeys.has(k) ? (persistent++) : added.push(f));
  for (const [k, f] of bKeys) if (!aKeys.has(k)) removed.push(f);

  return NextResponse.json({
    a: { id, total: a.length },
    b: { id: other, total: b.length },
    added: added.sort((x, y) => severityRank(y.severity) - severityRank(x.severity)),
    removed: removed.sort((x, y) => severityRank(y.severity) - severityRank(x.severity)),
    persistent,
    summary: {
      newCriticals: added.filter((f) => f.severity === "critical").length,
      newHighs: added.filter((f) => f.severity === "high").length,
      fixed: removed.length,
    },
  });
}

function severityRank(s: string): number {
  return ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 } as Record<string, number>)[s] ?? 0;
}

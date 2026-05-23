/**
 * GET /api/scans/[id]/sbom-diff/[other]
 *
 * Compares the dependency surface of two source scans:
 *   - added:        deps in [id] but not in [other]
 *   - removed:      deps in [other] but not in [id]
 *   - version-bumped: same name, different version
 *   - new-vulns:    deps that newly carry a CVE in [id]
 *
 * The "deps" are extracted from any finding whose `evidence.pkg` /
 * `evidence.purl` / `evidence.installed` is set — i.e. trivy / osv-scanner /
 * snyk / dependency-track findings.
 */

import { NextResponse } from "next/server";
import { listFindings } from "@/lib/store";
import type { Finding } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface DepRef {
  name: string;
  version?: string;
  cves: string[];
}

function depsOf(findings: Finding[]): Map<string, DepRef> {
  const map = new Map<string, DepRef>();
  for (const f of findings) {
    const ev = f.evidence as { pkg?: string; purl?: string; installed?: string; version?: string } | undefined;
    if (!ev) continue;
    const name = ev.pkg ?? (ev.purl ? ev.purl.split("@")[0].split(":").pop() : undefined);
    if (!name) continue;
    const version = ev.installed ?? ev.version;
    const cur = map.get(name) ?? { name, version, cves: [] };
    if (version && !cur.version) cur.version = version;
    if (f.cve) for (const c of f.cve) if (!cur.cves.includes(c)) cur.cves.push(c);
    map.set(name, cur);
  }
  return map;
}

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/sbom-diff/[other]">) {
  const { id, other } = await ctx.params;
  const [a, b] = await Promise.all([listFindings(id), listFindings(other)]);
  const aDeps = depsOf(a), bDeps = depsOf(b);

  const added: DepRef[] = [];
  const removed: DepRef[] = [];
  const versionBumped: { name: string; from: string; to: string; newCves: string[] }[] = [];
  const newVulns: { name: string; version?: string; cves: string[] }[] = [];

  for (const [name, ref] of aDeps) {
    const prev = bDeps.get(name);
    if (!prev) {
      added.push(ref);
      continue;
    }
    if (ref.version && prev.version && ref.version !== prev.version) {
      const newCves = ref.cves.filter((c) => !prev.cves.includes(c));
      versionBumped.push({ name, from: prev.version, to: ref.version, newCves });
    }
    const cveDelta = ref.cves.filter((c) => !prev.cves.includes(c));
    if (cveDelta.length) newVulns.push({ name, version: ref.version, cves: cveDelta });
  }
  for (const [name, ref] of bDeps) if (!aDeps.has(name)) removed.push(ref);

  return NextResponse.json({
    a: { id, total: aDeps.size },
    b: { id: other, total: bDeps.size },
    added,
    removed,
    versionBumped,
    newVulns,
    summary: {
      added: added.length,
      removed: removed.length,
      bumped: versionBumped.length,
      newVulnerableDeps: newVulns.length,
      newCVECount: newVulns.reduce((acc, v) => acc + v.cves.length, 0),
    },
  });
}

/**
 * GET /api/scans/[id]/sbom/[format]
 * format ∈ { cyclonedx, spdx }
 *
 * Builds an SBOM from every dep-shaped finding (trivy / osv / snyk / dt /
 * lockfile-lint). Output is industry-standard:
 *   - CycloneDX 1.5 JSON (NIST / OWASP recommendation)
 *   - SPDX 2.3 JSON (Linux Foundation / FOSSA / GitHub default)
 *
 * Use it: upload to Dependency-Track, attach to GitHub release, feed FOSSA.
 */

import { NextResponse } from "next/server";
import { listFindings, getScan } from "@/lib/store";
import type { Finding } from "@/lib/types";
import { randomUUID } from "node:crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface Component { name: string; version?: string; purl?: string; cves: string[]; sourceFile?: string }

function extract(findings: Finding[]): Component[] {
  const map = new Map<string, Component>();
  for (const f of findings) {
    const ev = f.evidence as { pkg?: string; purl?: string; installed?: string; version?: string; name?: string } | undefined;
    if (!ev) continue;
    const name = ev.pkg ?? ev.name;
    if (!name) continue;
    const purl = ev.purl;
    const version = ev.installed ?? ev.version;
    const key = purl ?? `${name}@${version ?? "?"}`;
    const cur = map.get(key) ?? { name, version, purl, cves: [], sourceFile: f.location.file };
    if (f.cve) for (const c of f.cve) if (!cur.cves.includes(c)) cur.cves.push(c);
    map.set(key, cur);
  }
  return [...map.values()];
}

function toCycloneDX(scanId: string, target: string, components: Component[]) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "moba-scanner", name: "moba-scanner", version: "0.1" }],
      component: { type: "application", name: target, "bom-ref": `target-${scanId}` },
    },
    components: components.map((c) => ({
      type: "library",
      name: c.name,
      ...(c.version ? { version: c.version } : {}),
      ...(c.purl ? { purl: c.purl } : { purl: `pkg:generic/${encodeURIComponent(c.name)}${c.version ? "@" + encodeURIComponent(c.version) : ""}` }),
      "bom-ref": c.purl ?? `${c.name}@${c.version ?? "0"}`,
    })),
    vulnerabilities: components.flatMap((c) => c.cves.map((cve) => ({
      id: cve,
      affects: [{ ref: c.purl ?? `${c.name}@${c.version ?? "0"}` }],
    }))),
  };
}

function toSpdx(scanId: string, target: string, components: Component[]) {
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `moba-scanner SBOM for ${target}`,
    documentNamespace: `https://moba-scanner.local/sbom/${scanId}`,
    creationInfo: {
      created: new Date().toISOString(),
      creators: ["Tool: moba-scanner-0.1"],
    },
    packages: [
      {
        SPDXID: "SPDXRef-Package-Root",
        name: target,
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        primaryPackagePurpose: "APPLICATION",
      },
      ...components.map((c, i) => ({
        SPDXID: `SPDXRef-Package-${i + 1}`,
        name: c.name,
        ...(c.version ? { versionInfo: c.version } : {}),
        downloadLocation: c.purl ?? "NOASSERTION",
        filesAnalyzed: false,
        ...(c.purl ? { externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: c.purl }] } : {}),
      })),
    ],
    relationships: components.map((_, i) => ({
      spdxElementId: "SPDXRef-Package-Root",
      relatedSpdxElement: `SPDXRef-Package-${i + 1}`,
      relationshipType: "DEPENDS_ON",
    })),
  };
}

export async function GET(_req: Request, ctx: RouteContext<"/api/scans/[id]/sbom/[format]">) {
  const { id, format } = await ctx.params;
  if (format !== "cyclonedx" && format !== "spdx") return NextResponse.json({ error: "format must be 'cyclonedx' or 'spdx'" }, { status: 400 });
  const scan = await getScan(id);
  if (!scan) return NextResponse.json({ error: "not found" }, { status: 404 });
  const findings = await listFindings(id);
  const components = extract(findings);
  const out = format === "cyclonedx" ? toCycloneDX(id, scan.target.value, components) : toSpdx(id, scan.target.value, components);
  return new NextResponse(JSON.stringify(out, null, 2), {
    headers: {
      "Content-Type": format === "cyclonedx" ? "application/vnd.cyclonedx+json" : "application/spdx+json",
      "Content-Disposition": `attachment; filename="moba-${id}.${format === "cyclonedx" ? "cdx.json" : "spdx.json"}"`,
    },
  });
}

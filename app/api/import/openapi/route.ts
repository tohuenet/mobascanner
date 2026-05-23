/**
 * POST /api/import/openapi — accepts an OpenAPI 3.x spec (JSON or YAML)
 * and creates a synthetic SiteMap from every operation it declares.
 *
 * Useful when the API has no HTML surface for the crawler — a backend-only
 * service. Every `(operation, parameter)` becomes a probe target for SQLi,
 * NoSQLi, BOLA (path id pivot), mass-assignment, etc.
 */

import { NextResponse, type NextRequest } from "next/server";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { createScan } from "@/lib/store";
import { makeScan } from "@/lib/engine/runner";
import { saveSiteMap, type SiteMap, type SiteMapForm, type SiteMapPage } from "@/lib/web/sitemap";
import "@/lib/scanners";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const REQ = z.object({
  spec: z.string(),
  baseUrl: z.string().url().optional(),
  target: z.object({ value: z.string().url() }),
});

interface OpenApiSpec {
  servers?: Array<{ url: string }>;
  paths?: Record<string, Record<string, {
    parameters?: Array<{ name: string; in: string; required?: boolean; schema?: { type?: string } }>;
    requestBody?: { content?: Record<string, { schema?: { properties?: Record<string, unknown>; type?: string } }> };
  }>>;
}

function parseSpec(spec: string): OpenApiSpec {
  // JSON only — keeps deps small; YAML users can convert via `yq`.
  return JSON.parse(spec);
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = REQ.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid body", details: parsed.error.flatten() }, { status: 400 });

  let spec: OpenApiSpec;
  try { spec = parseSpec(parsed.data.spec); }
  catch (e) { return NextResponse.json({ error: `invalid OpenAPI JSON: ${e instanceof Error ? e.message : String(e)}` }, { status: 400 }); }

  const baseUrl = parsed.data.baseUrl ?? spec.servers?.[0]?.url ?? parsed.data.target.value;
  const targetOrigin = new URL(baseUrl).origin;
  const scanId = randomUUID();
  const pages: SiteMapPage[] = [];
  const forms: SiteMapForm[] = [];

  for (const [path, ops] of Object.entries(spec.paths ?? {})) {
    for (const [method, op] of Object.entries(ops)) {
      const methodU = method.toUpperCase() as SiteMapPage["method"];
      // Build a sample URL: replace `{param}` with `1`.
      const samplePath = path.replace(/\{[^}]+\}/g, "1");
      let url: string;
      try { url = new URL(samplePath, baseUrl + (baseUrl.endsWith("/") ? "" : "/")).toString(); } catch { continue; }

      // For GET / DELETE: query params become URL params (we synthesize one URL
      // per param key set).
      const urlObj = new URL(url);
      for (const p of op.parameters ?? []) {
        if (p.in === "query") urlObj.searchParams.set(p.name, p.schema?.type === "integer" ? "1" : "x");
      }
      pages.push({
        url: urlObj.toString(), method: methodU, status: 0,
        contentType: "application/json",
        interestScore: 0.7, // API-like → high interest
      });
      // For POST / PUT / PATCH with a body schema, synthesize a JSON form.
      if (["POST", "PUT", "PATCH"].includes(methodU) && op.requestBody) {
        const jsonContent = op.requestBody.content?.["application/json"];
        if (jsonContent?.schema?.properties) {
          forms.push({
            pageUrl: urlObj.toString(),
            action: urlObj.toString(),
            method: "POST",
            inputs: Object.keys(jsonContent.schema.properties).map((name) => ({ name, type: "text", value: "" })),
            looksLikeLogin: /login|signin|sign-in|authenticate/i.test(path),
            hasCsrfToken: false,
          });
        }
      }
    }
  }

  const map: SiteMap = {
    scanId, origin: targetOrigin, pages, forms,
    apiHints: pages.map((p) => ({ url: p.url, source: "openapi" })),
    cookies: {}, technologies: ["OpenAPI-imported"], builtAt: Date.now(),
  };

  const scan = makeScan({
    id: scanId, kind: "web",
    target: { value: parsed.data.target.value, type: "url" },
    selection: { enabled: [] },
  });
  await createScan(scan);
  await saveSiteMap(map);

  return NextResponse.json({
    scanId, operations: pages.length, forms: forms.length,
    nextStep: `Kick off /api/scans with kind=web; the SQLi / form-fuzzer / mass-assignment scanners will pick up the synthesized SiteMap.`,
  }, { status: 201 });
}

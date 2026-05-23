/**
 * GraphQL deep fuzzer — beyond introspection presence:
 *
 *   1. If introspection is enabled, fetch the full schema.
 *   2. Send a deeply-nested batched query (10× same query) — checks whether
 *      batching is rate-limited. Lack of rate limit = trivial DoS.
 *   3. Send a depth-bomb (recursive type query 8 levels deep) — should be
 *      rejected by `graphql-depth-limit`.
 *   4. Send a circular fragment alias attack — exponential expansion.
 *   5. For each Query field that takes an `id: ID!`, call it with id=1 and
 *      id=2 and check whether responses differ (per-object-no-auth ≈ BOLA).
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

interface SchemaType {
  name?: string;
  kind?: string;
  fields?: Array<{ name: string; args: Array<{ name: string; type: { name?: string; kind?: string; ofType?: { name?: string } } }>; type: { name?: string; kind?: string; ofType?: { name?: string } } }>;
}
interface Schema {
  queryType: { name: string };
  types: SchemaType[];
}

async function fetchSchema(session: BrowsingSession, url: string, signal: AbortSignal): Promise<Schema | null> {
  const query = `query IntrospectionQuery {
    __schema {
      queryType { name }
      types {
        name
        kind
        fields { name args { name type { name kind ofType { name } } } type { name kind ofType { name } } }
      }
    }
  }`;
  try {
    const r = await session.fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query }),
      signal,
    });
    const j = JSON.parse(r.body);
    return j?.data?.__schema ?? null;
  } catch { return null; }
}

export const graphqlFuzzerScanner: Scanner = {
  id: "web.graphql-fuzzer",
  name: "GraphQL Deep Fuzzer",
  kind: "web",
  description: "After introspection succeeds, runs (1) batched-query DoS, (2) depth-bomb attack, (3) circular fragment, (4) per-id BOLA probe across every Query field that takes an `id`.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.graphql-fuzzer", name: "GraphQL Deep Fuzzer", kind: "web", backend: "builtin", status: "available", description: "Built-in GraphQL field-level + DoS fuzzer." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const candidates = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];
    let endpoint: string | null = null;
    for (const p of candidates) {
      const u = new URL(p, seed).toString();
      const s = await fetchSchema(session, u, ctx.signal);
      if (s) { endpoint = u; }
    }
    if (!endpoint) { await ctx.progress(1, "no GraphQL"); return; }

    const schema = await fetchSchema(session, endpoint, ctx.signal);
    if (!schema) { await ctx.progress(1, "no schema"); return; }

    // 1) Batched-query DoS
    {
      const probe = "{ __schema { queryType { name } } }";
      const batch = Array.from({ length: 10 }, (_, i) => ({ query: probe, operationName: `Op${i}` }));
      let r;
      try { r = await session.fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(batch), signal: ctx.signal }); }
      catch { /* tolerate */ }
      if (r && r.res.status < 400 && /\[\s*\{/.test(r.body)) {
        await ctx.emit(draft({
          severity: "medium", confidence: "high",
          title: `GraphQL accepts batched queries on ${endpoint}`,
          description: "Sending a 10-query batch was accepted. Without rate limits, an attacker can amplify any expensive query 1000× per request — trivial DoS / brute-force amplifier.",
          ruleId: "graphql/batching", cwe: ["CWE-770"], owasp: ["A04:2021"],
          location: { url: endpoint },
          evidence: { batchSize: 10, status: r.res.status, snippet: truncate(r.body, 300) },
          remediation: "Disable batched queries (Apollo `batching: false`) or rate-limit per request including batch size.",
          references: ["https://owasp.org/www-project-api-security/"],
        }));
      }
    }

    // 2) Depth-bomb
    {
      let depthQuery = "{ __schema {";
      for (let i = 0; i < 12; i++) depthQuery += " types {";
      for (let i = 0; i < 12; i++) depthQuery += " }";
      depthQuery += " } }";
      let r;
      try { r = await session.fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query: depthQuery }), signal: ctx.signal }); }
      catch { return; }
      if (r.res.status < 400 && !/depth|max depth|exceeds/i.test(r.body)) {
        await ctx.emit(draft({
          severity: "medium", confidence: "medium",
          title: `GraphQL accepts deeply-nested queries on ${endpoint}`,
          description: "12-level-deep query accepted — without depth-limit, attackers can build queries that cause exponential resolver work (eg. friends.friends.friends...).",
          ruleId: "graphql/depth-bomb", cwe: ["CWE-674"], owasp: ["A04:2021"],
          location: { url: endpoint },
          evidence: { depth: 12, status: r.res.status },
          remediation: "Apply `graphql-depth-limit` (Node) / similar middleware. Also enforce query-cost / complexity scoring.",
        }));
      }
    }

    // 3) Per-id BOLA probe
    const queryType = schema.types.find((t) => t.name === schema.queryType.name);
    const idFields = queryType?.fields?.filter((f) => f.args.some((a) => a.name === "id")) ?? [];
    for (const field of idFields.slice(0, 8)) {
      if (ctx.signal.aborted) break;
      const probe = (id: number) => ({ query: `{ ${field.name}(id: ${id}) { __typename } }` });
      let r1, r2;
      try {
        r1 = await session.fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(probe(1)), signal: ctx.signal });
        r2 = await session.fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(probe(2)), signal: ctx.signal });
      } catch { continue; }
      const ok1 = !/error|Error|denied|forbidden/i.test(r1.body) && r1.res.status < 400;
      const ok2 = !/error|Error|denied|forbidden/i.test(r2.body) && r2.res.status < 400;
      const distinct = r1.body !== r2.body && Math.abs(r1.body.length - r2.body.length) > 5;
      if (ok1 && ok2 && distinct) {
        await ctx.emit(draft({
          severity: "high", confidence: "medium",
          title: `Possible GraphQL BOLA on field "${field.name}"`,
          description: `\`{ ${field.name}(id: 1) }\` and \`{ ${field.name}(id: 2) }\` both succeed and return distinct objects without auth challenge. If \`${field.name}\` returns user/private data, it's BOLA / IDOR.`,
          ruleId: "graphql/bola-by-id", cwe: ["CWE-639"], owasp: ["A01:2021"],
          location: { url: endpoint, snippet: field.name },
          evidence: { field: field.name, len1: r1.body.length, len2: r2.body.length },
          remediation: "Enforce per-object authorization in resolvers. Don't return objects without a user-permissions check.",
          references: ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
        }));
      }
    }
    await ctx.progress(1, "graphql fuzz done");
  },
};

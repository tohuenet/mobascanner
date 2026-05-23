/**
 * Custom-rules scanner — runs every YAML/JSON rule loaded from `rules/`.
 *
 * Each rule is one HTTP probe + ≥1 assertion. Findings emit through the
 * same pipeline as built-in scanners; the rule's `severity` maps directly,
 * `ruleId` becomes the Finding `ruleId`, `cwe`/`owasp`/`cve` flow through.
 */

import path from "node:path";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";
import { loadRules, type Rule } from "../../rules/dsl";

const RULES_DIR = path.join(process.cwd(), "rules");

let cachedRules: Rule[] | null = null;
let cachedAt = 0;
const CACHE_TTL_MS = 30_000; // hot-reload friendly during dev

async function getRules(): Promise<Rule[]> {
  if (cachedRules && Date.now() - cachedAt < CACHE_TTL_MS) return cachedRules;
  const rules = await loadRules(RULES_DIR);
  cachedRules = rules;
  cachedAt = Date.now();
  return rules;
}

function checkMatch(probe: Rule["targets"][number], r: { status: number; body: string; headers: Headers; latencyMs: number }): boolean {
  const m = probe.match;
  if (m.status && !m.status.includes(r.status)) return false;
  if (m.body_contains) for (const s of m.body_contains) if (!r.body.includes(s)) return false;
  if (m.body_regex) {
    let re;
    try { re = new RegExp(m.body_regex); } catch { return false; }
    if (!re.test(r.body)) return false;
  }
  if (m.header) {
    const v = r.headers.get(m.header.name) ?? "";
    if (!v.toLowerCase().includes(m.header.contains.toLowerCase())) return false;
  }
  if (m.max_latency_ms !== undefined && r.latencyMs > m.max_latency_ms) return false;
  if (m.min_latency_ms !== undefined && r.latencyMs < m.min_latency_ms) return false;
  return true;
}

export const customRulesScanner: Scanner = {
  id: "web.custom-rules",
  name: "Custom Rules (YAML/JSON)",
  kind: "web",
  description: "Loads every `.yaml` / `.yml` / `.json` file from the `rules/` directory at the project root and runs each as a per-target probe. Lets users / security teams ship rules without TypeScript.",
  defaultEnabled: true,
  async tool() {
    const n = (await getRules()).length;
    return {
      id: "web.custom-rules", name: "Custom Rules", kind: "web", backend: "builtin",
      status: "available",
      description: `Built-in YAML/JSON rule runner — ${n} rule(s) loaded from ./rules/.`,
    };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const rules = await getRules();
    if (!rules.length) { await ctx.log("info", "no custom rules — drop YAML/JSON in ./rules/"); await ctx.progress(1, "no rules"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    let probes = 0;
    for (const rule of rules) {
      if (ctx.signal.aborted) break;
      const pageList = (() => {
        if (rule.forEachPage && map) return map.pages.map((p) => p.url);
        return [seed.toString()];
      })()
        .filter((u) => {
          if (!rule.pageRegex) return true;
          try { return new RegExp(rule.pageRegex).test(u); } catch { return true; }
        });
      for (const targetUrl of pageList) {
        if (ctx.signal.aborted) break;
        for (const probe of rule.targets) {
          if (ctx.signal.aborted) break;
          let url;
          try { url = new URL(probe.path, targetUrl).toString(); } catch { continue; }
          const t = Date.now();
          let r;
          try {
            r = await session.fetch(url, {
              method: probe.method.toUpperCase(),
              headers: probe.headers ?? {},
              body: probe.body,
              signal: ctx.signal,
            });
          } catch { continue; }
          probes++;
          const matched = checkMatch(probe, { status: r.res.status, body: r.body, headers: r.res.headers, latencyMs: Date.now() - t });
          if (!matched) continue;
          await ctx.emit(draft({
            severity: rule.severity, confidence: "medium",
            title: rule.name + (pageList.length > 1 ? ` on ${url}` : ""),
            description: rule.description,
            ruleId: rule.ruleId ?? `custom/${rule.id}`,
            cwe: rule.cwe, owasp: rule.owasp, cve: rule.cve,
            location: { url },
            evidence: { matchedProbe: probe, status: r.res.status, snippet: truncate(r.body, 300) },
            remediation: rule.remediation,
            references: rule.references,
          }));
          break; // one probe match per rule per page is enough.
        }
      }
    }
    await ctx.progress(1, `${probes} probes for ${rules.length} rule(s)`);
  },
};

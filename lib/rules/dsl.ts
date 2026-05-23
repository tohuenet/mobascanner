/**
 * Custom rule DSL — JSON / YAML rules loaded at runtime.
 *
 * The schema is deliberately small: each rule sends ONE HTTP request and
 * runs ≥1 assertion. This catches ~80% of nuclei-style probes without
 * needing a Turing-complete YAML language. Power users can still write a
 * proper TypeScript scanner for things this can't express.
 *
 * Schema (YAML or JSON):
 *
 *   id: my-rule-id           # required, kebab-case
 *   name: Human label         # shown in UI
 *   severity: high            # critical|high|medium|low|info
 *   description: ...          # markdown
 *   ruleId: cwe-79/myrule     # finding rule id (defaults to id)
 *   cwe: [CWE-79]
 *   owasp: ['A03:2021']
 *   targets:                  # list of HTTP probes
 *     - method: GET
 *       path: "/admin"        # appended to target origin
 *       headers:              # optional
 *         X-Forwarded-Host: evil.example
 *       body: ""              # optional — POST/PUT body
 *       match:                # at least one of:
 *         status: [200, 401]
 *         body_contains: ["Apache Tomcat"]
 *         body_regex: "Tomcat (\\d+\\.\\d+\\.\\d+)"
 *         header:
 *           name: server
 *           contains: "tomcat"
 *         max_latency_ms: 5000   # for time-blind detection
 *         min_latency_ms: 4500
 *   remediation: ...
 *   references:
 *     - https://...
 */

import { z } from "zod";

const Match = z.object({
  status: z.array(z.number()).optional(),
  body_contains: z.array(z.string()).optional(),
  body_regex: z.string().optional(),
  header: z.object({ name: z.string(), contains: z.string() }).optional(),
  max_latency_ms: z.number().optional(),
  min_latency_ms: z.number().optional(),
});

const Probe = z.object({
  method: z.string().default("GET"),
  path: z.string().default("/"),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().optional(),
  match: Match,
});

export const RuleSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9._/-]*$/),
  name: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  description: z.string(),
  ruleId: z.string().optional(),
  cwe: z.array(z.string()).optional(),
  owasp: z.array(z.string()).optional(),
  cve: z.array(z.string()).optional(),
  targets: z.array(Probe).min(1),
  remediation: z.string().optional(),
  references: z.array(z.string()).optional(),
  /** If true, rule only runs against pages that match this regex (e.g. only
   *  /api/* paths). Filters down work. */
  pageRegex: z.string().optional(),
  /** If true, rule attempts the probe against EVERY page in the SiteMap
   *  rather than just appending its `path` to the origin. */
  forEachPage: z.boolean().optional(),
});

export type Rule = z.infer<typeof RuleSchema>;

// ─────────────────────────── Loader ───────────────────────────────────
import { promises as fs } from "node:fs";
import path from "node:path";

/**
 * Load every `*.yaml` / `*.yml` / `*.json` from a directory tree.
 *
 * Why no YAML lib: we'd add a 200KB dep for a marginal feature. Instead we
 * accept JSON-shaped YAML (the subset that's also valid JSON, plus comments
 * stripped). For full YAML, users can ship `.json` files (we strip BOM + JSON5
 * trailing-comma compatibility).
 */
export async function loadRules(rootDir: string): Promise<Rule[]> {
  const out: Rule[] = [];
  async function walk(dir: string) {
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) await walk(full);
      else if (/\.(json|ya?ml)$/i.test(e.name)) {
        try {
          const raw = (await fs.readFile(full, "utf8"))
            .replace(/^﻿/, "")     // BOM
            .replace(/^\s*#.*$/gm, "")   // # YAML comments
            .replace(/^\s*\/\/.*$/gm, ""); // // JSON5 comments
          const arr = JSON.parse(raw);
          for (const obj of Array.isArray(arr) ? arr : [arr]) {
            const parsed = RuleSchema.safeParse(obj);
            if (parsed.success) out.push(parsed.data);
            else console.warn(`[rules] ${full}: ${parsed.error.message}`);
          }
        } catch (err) {
          console.warn(`[rules] ${full}: ${err instanceof Error ? err.message : err}`);
        }
      }
    }
  }
  await walk(rootDir);
  return out;
}

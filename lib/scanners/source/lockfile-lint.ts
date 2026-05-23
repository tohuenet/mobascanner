/**
 * lockfile-lint adapter — built-in checks against npm/yarn/pnpm lockfiles
 * for typosquat-shaped names, unexpected registries, and integrity-mismatch
 * surface.
 *
 * No external dep — we parse the lockfile JSON / yaml directly.
 *
 * Detection rules:
 *   - Package resolved from a registry that's NOT registry.npmjs.org / GitHub
 *     (potential dependency-confusion / private-registry leak).
 *   - Package missing `integrity` field (no SHA verification at install).
 *   - Package name within Levenshtein 1-2 of a top-1k popular package
 *     (typosquat hint — limited list to avoid heavyweight comparison).
 *   - Package whose registry URL uses HTTP instead of HTTPS.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { draft, type Scanner } from "../../engine/scanner";
import { resolveSourceTarget } from "./git-import";

interface LockEntry { name: string; resolved?: string; integrity?: string; version?: string }

const POPULAR_PKGS = new Set([
  "express", "react", "lodash", "axios", "vue", "moment", "chalk", "request",
  "commander", "debug", "cors", "body-parser", "mongoose", "passport", "bcrypt",
  "jsonwebtoken", "dotenv", "uuid", "validator", "yargs", "fs-extra", "glob",
  "minimatch", "pg", "mysql", "redis", "stripe", "mongodb", "fastify", "next",
  "prisma", "typescript",
]);

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
    dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  }
  return dp[a.length][b.length];
}

function findTyposquatHint(name: string): string | null {
  if (POPULAR_PKGS.has(name)) return null;
  for (const pop of POPULAR_PKGS) {
    if (Math.abs(name.length - pop.length) > 2) continue;
    const d = levenshtein(name, pop);
    if (d > 0 && d <= 2 && name !== pop) return pop;
  }
  return null;
}

function parseNpmLockV3(json: { packages?: Record<string, { resolved?: string; integrity?: string; version?: string }> }): LockEntry[] {
  const out: LockEntry[] = [];
  for (const [k, v] of Object.entries(json.packages ?? {})) {
    if (!k.startsWith("node_modules/")) continue;
    const name = k.slice("node_modules/".length).replace(/^.+?\//, ""); // strip nested scope path
    if (!name) continue;
    out.push({ name, resolved: v.resolved, integrity: v.integrity, version: v.version });
  }
  return out;
}
function parseNpmLockV1(json: { dependencies?: Record<string, { resolved?: string; integrity?: string; version?: string }> }): LockEntry[] {
  return Object.entries(json.dependencies ?? {}).map(([name, v]) => ({ name, resolved: v.resolved, integrity: v.integrity, version: v.version }));
}

export const lockfileLintScanner: Scanner = {
  id: "source.lockfile-lint",
  name: "Lockfile Lint",
  kind: "source",
  description: "Parses npm/yarn/pnpm lockfiles to flag (1) typosquat-shaped names, (2) packages resolved from non-canonical registries, (3) packages with no integrity field, (4) HTTP (non-HTTPS) registry URLs.",
  defaultEnabled: true,
  async tool() {
    return {
      id: "source.lockfile-lint", name: "Lockfile Lint", kind: "source", backend: "builtin", status: "available",
      description: "Built-in supply-chain lockfile auditor.",
      upstream: "https://github.com/lirantal/lockfile-lint",
    };
  },
  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const candidates = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"];
    let lockfile: string | null = null;
    let kind: "npm-v3" | "npm-v1" | "yarn" | "pnpm" | null = null;
    for (const c of candidates) {
      const full = path.join(root, c);
      try { await fs.access(full); lockfile = full; break; } catch { /* keep trying */ }
    }
    if (!lockfile) { await ctx.log("info", "no lockfile"); await ctx.progress(1, "skipped"); return; }
    await ctx.log("info", `lockfile: ${path.basename(lockfile)}`);

    let entries: LockEntry[] = [];
    if (lockfile.endsWith(".json")) {
      try {
        const json = JSON.parse(await fs.readFile(lockfile, "utf8"));
        if (json.lockfileVersion >= 2) { entries = parseNpmLockV3(json); kind = "npm-v3"; }
        else { entries = parseNpmLockV1(json); kind = "npm-v1"; }
      } catch (e) { await ctx.log("error", `parse: ${e instanceof Error ? e.message : e}`); return; }
    } else {
      // yarn.lock / pnpm — minimal regex parse for `name@x.y.z:` then `resolved "url"`
      const txt = await fs.readFile(lockfile, "utf8");
      const blocks = txt.split(/\n\n/);
      for (const b of blocks) {
        const nameMatch = /^"?([@a-z0-9./-]+)@/.exec(b);
        const resolved = /resolved\s+"([^"]+)"/.exec(b);
        const integrity = /integrity\s+([^\s\n"]+)/.exec(b);
        if (nameMatch) entries.push({ name: nameMatch[1].replace(/^@?\w+\//, ""), resolved: resolved?.[1], integrity: integrity?.[1] });
      }
      kind = lockfile.endsWith("yarn.lock") ? "yarn" : "pnpm";
    }

    let hits = 0;
    const seenNames = new Set<string>();
    for (const e of entries) {
      if (!e.name || seenNames.has(e.name)) continue;
      seenNames.add(e.name);
      // 1) Non-canonical registry
      if (e.resolved && !/registry\.npmjs\.org|github\.com|gitlab\.com|bitbucket\.org/.test(e.resolved)) {
        hits++;
        await ctx.emit(draft({
          severity: "medium", confidence: "medium",
          title: `Non-canonical registry: ${e.name} → ${new URL(e.resolved).hostname}`,
          description: `${e.name}@${e.version ?? "?"} is resolved from \`${e.resolved}\` — not the public npm registry. Confirm this is your private registry. If unintended, you have a dependency-confusion exposure.`,
          ruleId: "lockfile/non-canonical-registry",
          cwe: ["CWE-829"], owasp: ["A08:2021"],
          location: { file: path.relative(root, lockfile).replace(/\\/g, "/") },
          evidence: { name: e.name, version: e.version, resolved: e.resolved, lockKind: kind },
        }));
      }
      // 2) Missing integrity
      if (!e.integrity && e.resolved) {
        hits++;
        await ctx.emit(draft({
          severity: "low", confidence: "high",
          title: `Missing integrity hash: ${e.name}@${e.version}`,
          description: "Lockfile entry has no `integrity` field — install will not verify SHA-512 of the tarball. Tampered packages can be served at install time.",
          ruleId: "lockfile/no-integrity",
          cwe: ["CWE-353"], owasp: ["A08:2021"],
          location: { file: path.relative(root, lockfile).replace(/\\/g, "/") },
          evidence: { name: e.name, version: e.version },
        }));
      }
      // 3) HTTP registry URL
      if (e.resolved && /^http:\/\//.test(e.resolved)) {
        hits++;
        await ctx.emit(draft({
          severity: "high", confidence: "high",
          title: `HTTP registry URL: ${e.name} → ${e.resolved}`,
          description: "Package is fetched over plain HTTP. Network attackers can swap the tarball at install time.",
          ruleId: "lockfile/http-registry",
          cwe: ["CWE-319"], owasp: ["A02:2021", "A08:2021"],
          location: { file: path.relative(root, lockfile).replace(/\\/g, "/") },
          evidence: { name: e.name, resolved: e.resolved },
        }));
      }
      // 4) Typosquat
      const popular = findTyposquatHint(e.name);
      if (popular) {
        hits++;
        await ctx.emit(draft({
          severity: "medium", confidence: "low",
          title: `Possible typosquat: ${e.name} (similar to popular ${popular})`,
          description: `Package name "${e.name}" is within edit-distance 2 of the popular package "${popular}". Confirm intent — typosquats are how supply-chain attackers ship credential stealers via npm.`,
          ruleId: "lockfile/typosquat",
          cwe: ["CWE-829"], owasp: ["A08:2021"],
          location: { file: path.relative(root, lockfile).replace(/\\/g, "/") },
          evidence: { name: e.name, similarTo: popular },
        }));
      }
    }
    await ctx.progress(1, `${entries.length} packages, ${hits} findings`);
  },
};

/**
 * Correlation & Confirmation engine (Phase 1 — MVP).
 *
 * The product's competitive wedge: a finding is far more valuable when the
 * *source* side (SAST/SCA) and the *running* side (DAST) agree on it. moba
 * owns both; a DAST-only or source-only tool structurally cannot join them.
 *
 * `correlateFindings` is a pure function over the union of a project's member
 * findings. It does two joins and dedupes the result:
 *
 *   1. CVE-id cross-surface join — when the SAME CVE appears in BOTH a
 *      web-origin finding (live on the app) AND a source-origin finding (in a
 *      dependency), synthesize a high-confidence "Confirmed cross-surface"
 *      Finding. Origin is derived from the contributing finding's scannerId
 *      prefix (`web.` / `source.`), which every adapter follows.
 *
 *   2. Cross-kind chains — feed the union to the existing `detectChains` so the
 *      latent rules that need BOTH surfaces (`chain/cve-plus-secret`,
 *      `chain/db-port-plus-env`) finally fire; they were dead code before this
 *      because a single Scan is single-kind.
 *
 * Synthesized findings reuse the domain `Finding` model (scannerId
 * "correlation") — same synthesis style as `lib/triage/chains.ts`.
 */

import { createHash } from "node:crypto";
import { draft } from "../engine/scanner";
import { detectChains } from "../triage/chains";
import { triageFindings, mergeTriage } from "../triage/llm";
import type { Finding, Severity } from "../types";
import { listFindings } from "../store";
import { getProject, writeProjectFindings } from "../projects/store";

/** Sentinel scanId used by the pure core; `correlateProject` re-stamps it. */
const CORRELATION_SCAN = "correlation";
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const SEV_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

type Origin = "web" | "source" | "other";

/** Origin of a finding, derived from the adapter id convention "<kind>.<tool>". */
function originOf(f: Finding): Origin {
  const id = f.scannerId ?? "";
  if (id.startsWith("web.")) return "web";
  if (id.startsWith("source.")) return "source";
  return "other";
}

/** Extract normalized CVE ids (upper-case, canonical form) from a finding. */
function cvesOf(f: Finding): string[] {
  const out = new Set<string>();
  for (const raw of f.cve ?? []) {
    for (const m of raw.toUpperCase().matchAll(CVE_RE)) out.add(m[0].toUpperCase());
  }
  return [...out];
}

function maxSeverity(list: Finding[]): Severity {
  let best: Severity = "info";
  for (const f of list) {
    if (SEV_ORDER.indexOf(f.severity) > SEV_ORDER.indexOf(best)) best = f.severity;
  }
  return best;
}

/** Escalate one bucket (capped at critical) — justified by cross-validation. */
function bumpSeverity(s: Severity): Severity {
  const i = SEV_ORDER.indexOf(s);
  return SEV_ORDER[Math.min(SEV_ORDER.length - 1, i + 1)];
}

function uniq(list: string[]): string[] {
  return [...new Set(list.filter(Boolean))];
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}

/** Contributing finding ids recorded on a synthesized/composite finding. */
function contributorsOf(f: Finding): string[] {
  const c = f.evidence?.contributingFindings;
  return Array.isArray(c) ? c.filter((x): x is string => typeof x === "string") : [];
}

/** Stable id from the dedup key so re-runs produce identical finding ids. */
function stableId(key: string): string {
  return "corr-" + createHash("sha1").update(key).digest("hex").slice(0, 24);
}

/** Synthesize the headline CVE cross-surface finding from its contributors. */
function synthCveJoin(cveId: string, web: Finding[], source: Finding[]): Finding {
  const contributors = [...web, ...source];
  const refs = contributors.map((f) => f.id);
  const severity = bumpSeverity(maxSeverity(contributors));

  const w0 = web[0];
  const s0 = source[0];
  const pkg = str(s0.evidence?.pkg);
  const installed = str(s0.evidence?.installed);
  const fixed = str(s0.evidence?.fixed);
  const pkgLabel = pkg ? `${pkg}@${installed ?? "?"}` : "the vulnerable dependency";
  const liveUrl = w0.location.url ?? "the running application";

  const cve = uniq([cveId, ...contributors.flatMap(cvesOf)]);
  const cwe = uniq(contributors.flatMap((f) => f.cwe ?? []));
  const owasp = uniq(contributors.flatMap((f) => f.owasp ?? []));
  const cvss = Math.max(0, ...contributors.map((f) => f.cvss ?? 0)) || undefined;
  const references = uniq(contributors.flatMap((f) => f.references ?? [])).slice(0, 8);

  const base = draft({
    severity,
    confidence: "high",
    title: `Confirmed cross-surface: ${cveId} present in dependency AND live on the running app`,
    description:
      `${cveId} was independently flagged on BOTH surfaces of this project. ` +
      `Source/SCA reports it in ${pkgLabel}` +
      (s0.location.file ? ` (${s0.location.file})` : "") +
      `, and the running application exposes the same CVE live at ${liveUrl}. ` +
      `Agreement across code and runtime makes this a high-confidence, prioritized exploit path — ` +
      `not a theoretical dependency alert.`,
    ruleId: "correlation/cve-cross-surface",
    cwe: cwe.length ? cwe : undefined,
    cve: cve.length ? cve : undefined,
    owasp: owasp.length ? owasp : undefined,
    cvss,
    // Location from the web side — the live, reachable URL.
    location: { url: w0.location.url },
    evidence: {
      crossSurface: true,
      join: "cve",
      cveId,
      contributingFindings: refs,
      web: { scanId: w0.scanId, findingId: w0.id, url: w0.location.url, scanner: w0.scannerId },
      source: {
        scanId: s0.scanId,
        findingId: s0.id,
        pkg,
        installed,
        fixed,
        file: s0.location.file,
        scanner: s0.scannerId,
      },
    },
    remediation: fixed
      ? `Upgrade ${pkg ?? "the affected dependency"} to ${fixed} and redeploy — the running app currently ships the vulnerable version.`
      : `Patch or upgrade ${pkg ?? "the affected dependency"} and redeploy; the vulnerable code path is reachable in production.`,
    references: references.length ? references : undefined,
  });

  const key = ["cve", cveId, ...[...refs].sort()].join("|");
  return {
    ...base,
    id: stableId(key),
    scanId: CORRELATION_SCAN,
    scannerId: "correlation",
    scannerName: "Cross-surface Correlation",
    createdAt: Date.now(),
    correlation: { scanIds: uniq(contributors.map((f) => f.scanId)), join: "cve", contributes: refs },
  };
}

// ─────────────────── version-reachability join (Phase 2) ────────────────────
//
// Runtime side: `web.fingerprint` emits `evidence.liveVersions:[{pkg,version,
// ecosystem,…}]` — libraries/runtimes actually served by the live app. Source
// side: trivy emits `evidence:{pkg,installed,fixed}` per SCA finding. Joining
// them answers the question a DAST-only or source-only tool structurally can't:
// "is this vulnerable dependency actually shipped to production?"

/** A package observed live, plus the web finding (+ its scan) that saw it. */
interface LivePkg {
  version?: string;
  ecosystem?: string;
  webId: string;
  webScanId: string;
}

function normPkg(v: unknown): string | undefined {
  const s = str(v);
  return s ? s.toLowerCase() : undefined;
}

/**
 * Dependency-free, loose version normalization for an exact-equality compare
 * (we deliberately avoid a semver library / range logic — see task constraints).
 * Strips a leading `v` / range operator and any distro/pre-release suffix,
 * keeping the leading dotted-numeric core: `^4.17.21` → `4.17.21`,
 * `1.2.3-1ubuntu0.1` → `1.2.3`.
 */
function normVersion(v: unknown): string | undefined {
  const s = str(v);
  if (!s) return undefined;
  const cleaned = s.trim().replace(/^[v^~>=<\s]+/i, "");
  const m = /^(\d+(?:\.\d+){0,3})/.exec(cleaned);
  return m ? m[1] : undefined;
}

function versionsMatch(a: unknown, b: unknown): boolean {
  const na = normVersion(a);
  const nb = normVersion(b);
  return !!na && na === nb;
}

/**
 * Packages that genuinely ship to and execute in the browser. The
 * "not-observed-at-runtime" hint fires ONLY for these. Rationale: a frontend
 * fingerprint can only ever SEE client-side code, so "absent from the runtime
 * surface" is a meaningful signal ONLY for a library that WOULD have been served
 * if present. A Node.js *backend* dependency (express, ws, jsonwebtoken,
 * mongoose, …) lives in the same package.json but never reaches the browser —
 * emitting "lower runtime reachability" for it would be systematically wrong, so
 * we stay silent instead. Keep roughly aligned with web.fingerprint's detectable
 * client libraries.
 */
const BROWSER_LIBS = new Set<string>([
  "react", "react-dom", "preact", "vue", "@vue/runtime-dom", "@vue/reactivity",
  "angular", "@angular/core", "svelte", "solid-js", "alpinejs", "ember-source",
  "backbone", "underscore", "jquery", "zepto", "bootstrap", "@popperjs/core",
  "popper.js", "lodash", "lodash-es", "moment", "dayjs", "date-fns", "luxon",
  "axios", "d3", "chart.js", "three", "pixi.js", "gsap", "handlebars",
  "mustache", "marked", "dompurify", "core-js", "zone.js", "redux",
  "react-redux", "vuex", "rxjs", "immer", "formik",
]);

/** Build pkg → live-version map from every web-origin finding's liveVersions. */
function liveVersionsFrom(raw: Finding[]): Map<string, LivePkg> {
  const map = new Map<string, LivePkg>();
  for (const f of raw) {
    if (originOf(f) !== "web") continue;
    const lv = f.evidence?.liveVersions;
    if (!Array.isArray(lv)) continue;
    for (const entry of lv) {
      if (!entry || typeof entry !== "object") continue;
      const e = entry as Record<string, unknown>;
      const pkg = normPkg(e.pkg);
      if (!pkg) continue;
      const cand: LivePkg = { version: normVersion(e.version), ecosystem: str(e.ecosystem), webId: f.id, webScanId: f.scanId };
      const cur = map.get(pkg);
      // Deterministic collision resolution: prefer a concrete version, then the
      // lexicographically-smallest web finding id — so the chosen contributor
      // (and thus the synthesized id) is independent of input ordering.
      const better = !cur
        || (!!cand.version && !cur.version)
        || (!!cand.version === !!cur.version && cand.webId < cur.webId);
      if (better) map.set(pkg, cand);
    }
  }
  return map;
}

/**
 * Is a *source* SCA finding's package one the live frontend fingerprint could
 * plausibly SEE? Only then is "absent from the runtime surface" a meaningful,
 * de-prioritizing signal.
 *
 * We infer the ecosystem from the manifest trivy attributed the package to
 * (`location.file`). Client-observable = artifacts actually shipped to and run
 * in the browser: JS/npm manifests (bundled to the client) and `.js` targets.
 *
 * CRITICAL NUANCE — this is gated STRICTLY so we never deprioritize a backend
 * dependency just because a frontend fingerprint didn't see it. Every
 * server-side runtime (Ruby `Gemfile.lock`, Go `go.mod`/`go.sum`, Python
 * `requirements.txt`/`Pipfile`/`poetry.lock`, Java `pom.xml`/`*.gradle`, Rust
 * `Cargo.lock`, PHP `composer.lock`, OS/container packages) and every UNKNOWN
 * or missing manifest returns false: the DAST fingerprint has zero visibility
 * into code that executes server-side, so its absence there is NOT evidence of
 * absence and must leave the SCA finding untouched.
 */
function isClientObservableSource(f: Finding): boolean {
  const file = (str(f.location?.file) ?? "").toLowerCase();
  if (!file) return false;
  const base = file.split(/[\\/]/).pop() ?? file;
  if (/^(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(base)) return true;
  if (/\.js$/.test(base)) return true;
  return false; // server-side or unknown → never deprioritize
}

/** Headline: a vulnerable SCA package confirmed served live at the SAME version. */
function synthVersionReachable(source: Finding, live: LivePkg, pkg: string): Finding {
  const refs = uniq([source.id, live.webId]);
  const installed = str(source.evidence?.installed);
  const fixed = str(source.evidence?.fixed);
  const version = installed ?? live.version ?? "?";
  const cve = uniq(cvesOf(source));
  const cwe = uniq(source.cwe ?? []);
  const owasp = uniq(source.owasp ?? []);

  const base = draft({
    // Escalate one bucket (capped at critical) — cross-surface confirmation.
    severity: bumpSeverity(source.severity),
    confidence: "high",
    title: `Confirmed shipped to production: ${pkg}@${version} (vulnerable) is served live`,
    description:
      `SCA flagged ${pkg}@${version} as vulnerable in ${source.location.file ?? "the repository"}, and the ` +
      `running application serves the SAME package at the SAME version live ` +
      `(${live.ecosystem ?? "runtime"} artifact fingerprinted on the app). The vulnerable build is therefore ` +
      `reachable in production — this is a confirmed exploit path, not a build-only or transitive-only ` +
      `dependency alert. Prioritize accordingly.`,
    ruleId: "correlation/version-reachable",
    cve: cve.length ? cve : undefined,
    cwe: cwe.length ? cwe : undefined,
    owasp: owasp.length ? owasp : undefined,
    cvss: source.cvss,
    location: { file: source.location.file },
    evidence: {
      crossSurface: true,
      join: "version",
      pkg,
      installedVersion: installed,
      liveVersion: live.version,
      ecosystem: live.ecosystem,
      contributingFindings: refs,
      source: { scanId: source.scanId, findingId: source.id, scanner: source.scannerId, file: source.location.file, installed, fixed },
      web: { scanId: live.webScanId, findingId: live.webId },
    },
    remediation: fixed
      ? `Upgrade ${pkg} to ${fixed} and redeploy — the live app currently ships the vulnerable ${pkg}@${version}.`
      : `Patch/upgrade ${pkg} and redeploy; the vulnerable version is confirmed live in production.`,
    references: source.references?.slice(0, 8),
  });

  const key = ["version", ...[...refs].sort()].join("|");
  return {
    ...base,
    id: stableId(key),
    scanId: CORRELATION_SCAN,
    scannerId: "correlation",
    scannerName: "Cross-surface Correlation",
    createdAt: Date.now(),
    correlation: { scanIds: uniq([source.scanId, live.webScanId]), join: "version", contributes: refs },
  };
}

/** Conservative note: package IS live, but at a different version than flagged. */
function synthVersionMismatch(source: Finding, live: LivePkg, pkg: string): Finding {
  const refs = uniq([source.id, live.webId]);
  const installed = str(source.evidence?.installed);
  const base = draft({
    severity: "info",
    confidence: "low",
    title: `Possible: ${pkg} served live but at a different version than SCA flagged`,
    description:
      `SCA flagged ${pkg}@${installed ?? "?"} in ${source.location.file ?? "the repository"}; the live app serves ` +
      `${pkg}@${live.version} instead. The specific vulnerable build may not be the one deployed — verify which ` +
      `version production actually runs before acting on this dependency alert.`,
    ruleId: "correlation/version-mismatch",
    cve: cvesOf(source).length ? uniq(cvesOf(source)) : undefined,
    location: { file: source.location.file },
    evidence: {
      crossSurface: true,
      join: "version",
      pkg,
      installedVersion: installed,
      liveVersion: live.version,
      ecosystem: live.ecosystem,
      contributingFindings: refs,
      source: { scanId: source.scanId, findingId: source.id, scanner: source.scannerId },
      web: { scanId: live.webScanId, findingId: live.webId },
    },
  });
  const key = ["version-mismatch", ...[...refs].sort()].join("|");
  return {
    ...base,
    id: stableId(key),
    scanId: CORRELATION_SCAN,
    scannerId: "correlation",
    scannerName: "Cross-surface Correlation",
    createdAt: Date.now(),
    correlation: { scanIds: uniq([source.scanId, live.webScanId]), join: "version", contributes: refs },
  };
}

/** Low/info hint: a client-observable SCA package was NOT observed served live. */
function synthNotObserved(source: Finding, pkg: string): Finding {
  const refs = [source.id];
  const installed = str(source.evidence?.installed);
  const base = draft({
    // Additive hint only — we NEVER mutate/delete the original SCA finding.
    severity: source.severity === "info" ? "info" : "low",
    confidence: "low",
    title: `Not observed at runtime: ${pkg} flagged by SCA but not seen served live`,
    description:
      `SCA flagged ${pkg}@${installed ?? "?"} in ${source.location.file ?? "the repository"}, but the live ` +
      `fingerprint of the running app did not observe ${pkg} being served. Because ${pkg} is a library that ` +
      `normally ships to the browser, its absence from the runtime surface suggests LOWER runtime reachability ` +
      `(e.g. a build-only, dev, or tree-shaken dependency). This is a heuristic hint, NOT a ` +
      `dismissal — verify before deprioritizing.`,
    ruleId: "correlation/not-observed-at-runtime",
    cve: cvesOf(source).length ? uniq(cvesOf(source)) : undefined,
    cwe: source.cwe?.length ? uniq(source.cwe) : undefined,
    location: { file: source.location.file },
    evidence: {
      crossSurface: true,
      join: "version",
      notObservedLive: true,
      pkg,
      installedVersion: installed,
      ecosystem: "npm",
      contributingFindings: refs,
      source: { scanId: source.scanId, findingId: source.id, scanner: source.scannerId, file: source.location.file },
    },
    remediation:
      `Confirm whether ${pkg} actually reaches production (server logs, bundle analysis). If it is genuinely not ` +
      `deployed the SCA alert can be deprioritized; otherwise treat it at its original severity.`,
  });
  const key = ["not-observed", ...refs].join("|");
  return {
    ...base,
    id: stableId(key),
    scanId: CORRELATION_SCAN,
    scannerId: "correlation",
    scannerName: "Cross-surface Correlation",
    createdAt: Date.now(),
    correlation: { scanIds: uniq([source.scanId]), join: "version", contributes: refs },
  };
}

/**
 * Version-reachability join. For each source SCA finding with a concrete
 * `pkg@installed`, compare against what the live fingerprint served:
 *   - same version live  → headline "shipped to production" (escalated),
 *   - present but different version → conservative "possible" note,
 *   - present, live version unknown → skip (it IS live; can't confirm build),
 *   - absent AND a known browser-shipped library → low "not-observed" hint,
 *   - absent AND backend/unknown package → nothing (never deprioritize).
 */
function versionJoin(raw: Finding[]): Finding[] {
  const out: Finding[] = [];
  const live = liveVersionsFrom(raw);
  if (!live.size) return out; // no runtime version signal → nothing to join
  for (const s of raw) {
    if (originOf(s) !== "source") continue;
    const pkg = normPkg(s.evidence?.pkg);
    const installed = str(s.evidence?.installed);
    if (!pkg || !installed) continue; // need a concrete SCA pkg@version
    const hit = live.get(pkg);
    if (hit && hit.version && versionsMatch(hit.version, installed)) {
      out.push(synthVersionReachable(s, hit, pkg));
    } else if (hit && hit.version) {
      out.push(synthVersionMismatch(s, hit, pkg));
    } else if (hit && !hit.version) {
      // Package present live but live version unknown (e.g. name-only header
      // signal). It IS served, so do NOT emit a not-observed hint; we simply
      // can't confirm the exact build. Skip conservatively.
    } else if (isClientObservableSource(s) && BROWSER_LIBS.has(pkg)) {
      // Only for libraries that actually ship to the browser — a backend Node
      // dep in the same package.json is invisible to a frontend fingerprint, so
      // "not observed" there is not evidence of absence. See BROWSER_LIBS.
      out.push(synthNotObserved(s, pkg));
    }
  }
  return out;
}

/**
 * Dedupe correlated output by the (rule, sorted contributing-id set) key and
 * assign a deterministic id per key. Idempotent: the same union always yields
 * the same set of findings with the same ids.
 */
function dedupeCorrelated(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    const refs = contributorsOf(f);
    const key = [f.ruleId ?? f.scannerId, ...[...refs].sort()].join("|");
    if (!seen.has(key)) seen.set(key, { ...f, id: stableId(key) });
  }
  return [...seen.values()];
}

/**
 * Pure correlation core. Takes the union of a project's findings and returns
 * synthesized cross-surface + chain findings. Origin is read off each
 * finding's scannerId, so no extra input is needed. Deterministic + idempotent.
 */
export function correlateFindings(union: Finding[]): Finding[] {
  // Exclude previously-synthesized composites so we never feed our own output
  // (or a member scan's per-scan chains) back into the joins.
  const raw = union.filter((f) => f.scannerId !== "chain" && f.scannerId !== "correlation");

  const out: Finding[] = [];

  // 1) CVE-id cross-surface join.
  const byCve = new Map<string, Finding[]>();
  for (const f of raw) {
    for (const id of cvesOf(f)) {
      const arr = byCve.get(id);
      if (arr) arr.push(f);
      else byCve.set(id, [f]);
    }
  }
  for (const [cveId, group] of byCve) {
    const web = group.filter((f) => originOf(f) === "web");
    const source = group.filter((f) => originOf(f) === "source");
    if (web.length && source.length) out.push(synthCveJoin(cveId, web, source));
  }

  // 2) Version-reachability join — live fingerprint versions ↔ source SCA.
  out.push(...versionJoin(raw));

  // 3) Cross-kind chains over the union — latent rules finally fire.
  out.push(...detectChains(CORRELATION_SCAN, raw));

  // 4) Dedupe by contributing-id set (idempotent).
  return dedupeCorrelated(out);
}

function joinOf(f: Finding): "cve" | "chain" | "version" {
  if (f.ruleId === "correlation/cve-cross-surface") return "cve";
  if (f.ruleId?.startsWith("correlation/version") || f.ruleId === "correlation/not-observed-at-runtime") return "version";
  return "chain";
}

/**
 * Load the union of a project's member findings, correlate, optionally enrich
 * borderline joins via the LLM (only when ANTHROPIC_API_KEY is set — a clean
 * no-op otherwise), then persist idempotently. Returns the correlated set.
 */
export async function correlateProject(projectId: string): Promise<Finding[]> {
  const project = await getProject(projectId);
  if (!project) throw new Error(`project not found: ${projectId}`);

  // Union of every member scan's findings.
  const union: Finding[] = [];
  for (const m of project.members) {
    const findings = await listFindings(m.scanId);
    union.push(...findings);
  }

  // Pure core.
  let correlated = correlateFindings(union);

  // Stamp project linkage onto every synthesized finding. Chain findings don't
  // carry a `correlation` block yet, so resolve their contributing scan ids
  // from the union.
  const idToScan = new Map(union.map((f) => [f.id, f.scanId]));
  const scanIdsFor = (f: Finding) =>
    uniq(contributorsOf(f).map((id) => idToScan.get(id) ?? ""));
  correlated = correlated.map((f) => ({
    ...f,
    scanId: projectId,
    correlation: f.correlation
      ? { ...f.correlation, projectId }
      : { projectId, scanIds: scanIdsFor(f), join: joinOf(f), contributes: contributorsOf(f) },
  }));

  // Optional LLM confirmation — enhancer, never a hard dependency. Only the
  // borderline joins (not already confirmed-critical) go through triage.
  if (process.env.ANTHROPIC_API_KEY && correlated.length) {
    const borderline = correlated.filter((f) => !(f.severity === "critical" && f.confidence === "high"));
    if (borderline.length) {
      try {
        const { decisions, error } = await triageFindings(borderline);
        if (!error && decisions.length) {
          const merged = mergeTriage(borderline, decisions);
          const byId = new Map(merged.map((f) => [f.id, f]));
          correlated = correlated.map((f) => byId.get(f.id) ?? f);
        }
      } catch {
        // Enrichment is best-effort; correlation stands on its own without it.
      }
    }
  }

  await writeProjectFindings(projectId, correlated);
  return correlated;
}

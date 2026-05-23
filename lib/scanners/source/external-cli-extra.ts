/**
 * Additional source-side adapters:
 *
 *   - codeql           → GitHub's heavyweight SAST (db create + analyze)
 *   - trufflehog       → second-opinion secret scanner (verifies secrets)
 *   - detect-secrets   → Yelp's entropy-based secret scanner
 *   - snyk-code        → Snyk SAST (requires SNYK_TOKEN env)
 *   - dependency-track → SBOM upload to a Dependency-Track instance
 */

import path from "node:path";
import os from "node:os";
import { promises as fs } from "node:fs";
import { randomUUID } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, truncate } from "../common";
import { resolveSourceTarget } from "./git-import";

// ─────────────────────────── CodeQL ──────────────────────────────
export const codeqlScanner: Scanner = {
  id: "source.codeql",
  name: "CodeQL",
  kind: "source",
  description: "GitHub CodeQL — heavyweight semantic SAST. Builds a database, runs the standard query suite, returns SARIF.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("codeql", "--version");
    return {
      id: "source.codeql", name: "CodeQL", kind: "source", backend: "cli",
      cliCommand: "codeql", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "Download CodeQL CLI from https://github.com/github/codeql-cli-binaries/releases",
      upstream: "https://github.com/github/codeql",
      license: "GitHub CodeQL Terms (free for OSS / research)",
      description: "Semantic code analysis with thousands of curated queries.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("codeql", "--version");
    if (!v) { await ctx.log("warn", "codeql not found"); return; }

    const language = (ctx.options.language as string) || "javascript";
    const querySuite = (ctx.options.querySuite as string) || `codeql/${language}-queries`;
    const dbDir = path.join(os.tmpdir(), `codeql-db-${randomUUID()}`);
    const sarif = path.join(os.tmpdir(), `codeql-${randomUUID()}.sarif`);

    await ctx.log("info", `codeql ${v}, language=${language}`);
    await ctx.progress(0.1, "creating database");
    const create = await runCli("codeql", [
      "database", "create", dbDir,
      "--language", language,
      "--source-root", root,
      "--overwrite",
    ], { signal: ctx.signal, timeoutMs: 60 * 60 * 1000, maxBufferBytes: 256 * 1024 * 1024 });
    if (create.spawnError || create.code !== 0) {
      await ctx.log("error", `codeql db create failed: ${create.stderr.slice(0, 400)}`);
      return;
    }

    await ctx.progress(0.55, "analyzing");
    const analyze = await runCli("codeql", [
      "database", "analyze", dbDir,
      querySuite,
      "--format", "sarif-latest",
      "--output", sarif,
      "--rerun",
    ], { signal: ctx.signal, timeoutMs: 60 * 60 * 1000, maxBufferBytes: 256 * 1024 * 1024 });
    if (analyze.spawnError) { await ctx.log("error", analyze.stderr); return; }

    let report: { runs?: Array<{ tool: { driver: { rules?: Array<{ id: string; name?: string; shortDescription?: { text?: string }; properties?: { "security-severity"?: string; tags?: string[] } }> } }; results?: Array<{ ruleId: string; level?: string; message: { text?: string }; locations?: Array<{ physicalLocation?: { artifactLocation?: { uri?: string }; region?: { startLine?: number; startColumn?: number; snippet?: { text?: string } } } }> }> }> };
    try { report = JSON.parse(await fs.readFile(sarif, "utf8")); }
    catch { return; }
    finally {
      fs.rm(sarif, { force: true }).catch(() => {});
      fs.rm(dbDir, { recursive: true, force: true }).catch(() => {});
    }

    const ruleMap = new Map<string, { name?: string; description?: string; severity?: string; tags?: string[] }>();
    for (const run of report.runs ?? []) {
      for (const rule of run.tool.driver.rules ?? []) {
        ruleMap.set(rule.id, {
          name: rule.name,
          description: rule.shortDescription?.text,
          severity: rule.properties?.["security-severity"],
          tags: rule.properties?.tags,
        });
      }
      for (const res of run.results ?? []) {
        const rule = ruleMap.get(res.ruleId);
        const score = rule?.severity ? Number(rule.severity) : 0;
        const sev = score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score > 0 ? "low" : (res.level === "error" ? "high" : res.level === "warning" ? "medium" : "low");
        const loc = res.locations?.[0]?.physicalLocation;
        await ctx.emit(draft({
          severity: sev,
          confidence: "high",
          title: `CodeQL ${res.ruleId}: ${rule?.name ?? rule?.description ?? ""}`,
          description: res.message.text ?? "",
          ruleId: res.ruleId,
          cvss: score || undefined,
          location: {
            file: loc?.artifactLocation?.uri,
            line: loc?.region?.startLine,
            column: loc?.region?.startColumn,
            snippet: truncate(loc?.region?.snippet?.text ?? "", 300),
          },
          evidence: { tags: rule?.tags, level: res.level },
        }));
      }
    }
    await ctx.progress(1, "codeql done");
  },
};

// ─────────────────────────── trufflehog ──────────────────────────
export const trufflehogScanner: Scanner = {
  id: "source.trufflehog",
  name: "TruffleHog",
  kind: "source",
  description: "Truffle Security TruffleHog — verifies detected secrets by calling out to the issuing service. Yields very-high-confidence findings.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("trufflehog", "--version");
    return {
      id: "source.trufflehog", name: "TruffleHog", kind: "source", backend: "cli",
      cliCommand: "trufflehog", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`brew install trufflesecurity/trufflehog/trufflehog` / `go install github.com/trufflesecurity/trufflehog/v3@latest`",
      upstream: "https://github.com/trufflesecurity/trufflehog",
      license: "AGPL-3.0",
      description: "Secret scanner with live verification.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("trufflehog", "--version");
    if (!v) { await ctx.log("warn", "trufflehog not found"); return; }
    const r = await runCli("trufflehog", ["filesystem", root, "--json", "--no-update", "--only-verified"], {
      signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 128 * 1024 * 1024,
    });
    if (r.spawnError) return;
    let n = 0;
    for (const line of r.stdout.split(/\r?\n/)) {
      const t = line.trim();
      if (!t.startsWith("{")) continue;
      try {
        const obj = JSON.parse(t) as { DetectorName?: string; Verified?: boolean; SourceMetadata?: { Data?: { Filesystem?: { file?: string; line?: number } } }; Raw?: string };
        n += 1;
        await ctx.emit(draft({
          severity: obj.Verified ? "critical" : "high",
          confidence: obj.Verified ? "high" : "medium",
          title: `TruffleHog ${obj.Verified ? "verified " : ""}secret: ${obj.DetectorName}`,
          description: obj.Verified
            ? `TruffleHog confirmed this credential is currently valid by calling the upstream service.`
            : `Secret pattern matched but not verified.`,
          ruleId: `trufflehog/${obj.DetectorName}`,
          cwe: ["CWE-798"],
          owasp: ["A07:2021"],
          location: {
            file: obj.SourceMetadata?.Data?.Filesystem?.file ? path.relative(root, obj.SourceMetadata.Data.Filesystem.file).replace(/\\/g, "/") : undefined,
            line: obj.SourceMetadata?.Data?.Filesystem?.line,
            snippet: truncate(obj.Raw ?? "", 120),
          },
        }));
      } catch { /* ignore */ }
    }
    await ctx.progress(1, `${n} trufflehog findings`);
  },
};

// ──────────────────────── detect-secrets ─────────────────────────
export const detectSecretsScanner: Scanner = {
  id: "source.detect-secrets",
  name: "detect-secrets",
  kind: "source",
  description: "Yelp's detect-secrets — entropy-based + plugin-rule secret scanner. Good for catching custom token formats not covered by regex.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("detect-secrets", "--version");
    return {
      id: "source.detect-secrets", name: "detect-secrets", kind: "source", backend: "cli",
      cliCommand: "detect-secrets", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`pip install detect-secrets`",
      upstream: "https://github.com/Yelp/detect-secrets",
      license: "Apache-2.0",
      description: "Entropy + plugin-rule secret scanner.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("detect-secrets", "--version");
    if (!v) { await ctx.log("warn", "detect-secrets not found"); return; }
    const r = await runCli("detect-secrets", ["scan", root], { signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 128 * 1024 * 1024 });
    if (r.spawnError) return;
    if (!r.stdout.trim()) return;
    let parsed: { results?: Record<string, Array<{ type?: string; line_number?: number; hashed_secret?: string; is_verified?: boolean }>> };
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    let n = 0;
    for (const [file, matches] of Object.entries(parsed.results ?? {})) {
      for (const m of matches) {
        n += 1;
        await ctx.emit(draft({
          severity: m.is_verified ? "critical" : "high",
          confidence: m.is_verified ? "high" : "medium",
          title: `detect-secrets: ${m.type ?? "secret"} in ${file}`,
          description: `${m.type ?? "Secret pattern"} detected${m.is_verified ? " (verified)" : ""}.`,
          ruleId: `detect-secrets/${m.type}`,
          cwe: ["CWE-798"],
          location: { file: path.relative(root, file).replace(/\\/g, "/"), line: m.line_number },
          evidence: { hashed: m.hashed_secret },
        }));
      }
    }
    await ctx.progress(1, `${n} detect-secrets findings`);
  },
};

// ───────────────────────────── snyk ──────────────────────────────
export const snykScanner: Scanner = {
  id: "source.snyk",
  name: "Snyk",
  kind: "source",
  description: "Snyk CLI — runs Open Source (deps) + Code (SAST) scans. Requires `SNYK_TOKEN` in env.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("snyk", "--version");
    return {
      id: "source.snyk", name: "Snyk", kind: "source", backend: "cli",
      cliCommand: "snyk", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`npm install -g snyk` then `snyk auth`",
      upstream: "https://github.com/snyk/cli",
      license: "Apache-2.0 (CLI) / Proprietary (service)",
      description: "Snyk Open Source + Snyk Code.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("snyk", "--version");
    if (!v) { await ctx.log("warn", "snyk not found"); return; }
    if (!process.env.SNYK_TOKEN) await ctx.log("warn", "SNYK_TOKEN not set; rate-limited / unauthenticated mode");

    // 1. Open Source deps
    await ctx.progress(0.1, "snyk test (deps)");
    const test = await runCli("snyk", ["test", "--all-projects", "--json", `--directory=${root}`], {
      signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 128 * 1024 * 1024,
    });
    if (test.stdout.trim().startsWith("{") || test.stdout.trim().startsWith("[")) {
      try {
        const arr = JSON.parse(test.stdout);
        const projects = Array.isArray(arr) ? arr : [arr];
        for (const proj of projects) {
          for (const vu of proj.vulnerabilities ?? []) {
            await ctx.emit(draft({
              severity: vu.severity ?? "medium",
              confidence: "high",
              title: `snyk: ${vu.packageName}@${vu.version} — ${vu.id}`,
              description: vu.title ?? vu.description ?? "",
              ruleId: vu.id,
              cve: vu.identifiers?.CVE ?? [],
              cwe: vu.identifiers?.CWE ?? [],
              cvss: vu.cvssScore,
              location: { file: proj.displayTargetFile },
              references: vu.references?.map((r: { url?: string }) => r.url).filter(Boolean),
            }));
          }
        }
      } catch { /* fall through */ }
    }

    // 2. Snyk Code (SAST)
    await ctx.progress(0.55, "snyk code");
    const code = await runCli("snyk", ["code", "test", "--json", root], {
      signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 128 * 1024 * 1024,
    });
    if (code.stdout.trim().startsWith("{")) {
      try {
        const obj = JSON.parse(code.stdout);
        for (const run of obj.runs ?? []) {
          for (const res of run.results ?? []) {
            const loc = res.locations?.[0]?.physicalLocation;
            await ctx.emit(draft({
              severity: res.level === "error" ? "high" : res.level === "warning" ? "medium" : "low",
              confidence: "high",
              title: `Snyk Code: ${res.ruleId}`,
              description: res.message?.text ?? "",
              ruleId: `snyk-code/${res.ruleId}`,
              location: {
                file: loc?.artifactLocation?.uri,
                line: loc?.region?.startLine,
                column: loc?.region?.startColumn,
              },
            }));
          }
        }
      } catch { /* ignore */ }
    }

    await ctx.progress(1, "snyk done");
  },
};

// ──────────────────── Dependency-Track (SBOM upload) ─────────────
// We generate a CycloneDX SBOM via `cdxgen` (if installed) or `syft`,
// upload to a Dependency-Track instance, then fetch findings via API.
export const dependencyTrackScanner: Scanner = {
  id: "source.dependency-track",
  name: "Dependency-Track",
  kind: "source",
  description: "Generates a CycloneDX SBOM via syft/cdxgen, uploads to a Dependency-Track server, and pulls back findings. Requires options.dtUrl + options.dtKey + options.projectUuid (or projectName + projectVersion).",
  defaultEnabled: false,

  async tool() {
    const cdx = await detectCli("cdxgen", "--version");
    const syft = await detectCli("syft", "version");
    return {
      id: "source.dependency-track", name: "Dependency-Track", kind: "source", backend: "api",
      status: (cdx || syft) ? "available" : "missing",
      detectedVersion: cdx ?? syft ?? undefined,
      installHint: "Install one SBOM generator: `npm i -g @cyclonedx/cdxgen` or `brew install syft`. Run a Dependency-Track server (Docker compose recipe in upstream docs).",
      upstream: "https://github.com/DependencyTrack/dependency-track",
      license: "Apache-2.0",
      description: "SBOM-driven CVE intelligence platform.",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const dtUrl = (ctx.options.dtUrl as string)?.replace(/\/$/, "");
    const dtKey = ctx.options.dtKey as string;
    const projectUuid = ctx.options.projectUuid as string | undefined;
    const projectName = (ctx.options.projectName as string) || `moba-${ctx.scanId.slice(0, 8)}`;
    const projectVersion = (ctx.options.projectVersion as string) || "scan";
    if (!dtUrl || !dtKey) { await ctx.log("warn", "options.dtUrl and options.dtKey are required"); return; }

    await ctx.progress(0.1, "generating SBOM");
    const sbomPath = path.join(os.tmpdir(), `sbom-${randomUUID()}.json`);
    let gen;
    if (await detectCli("cdxgen", "--version")) {
      gen = await runCli("cdxgen", ["-r", "-o", sbomPath, root], { signal: ctx.signal, timeoutMs: 30 * 60 * 1000 });
    } else if (await detectCli("syft", "version")) {
      gen = await runCli("syft", [root, "-o", `cyclonedx-json=${sbomPath}`], { signal: ctx.signal, timeoutMs: 30 * 60 * 1000 });
    } else {
      await ctx.log("warn", "no SBOM tool available"); return;
    }
    if (gen.spawnError) { await ctx.log("error", gen.stderr); return; }

    let bom: string;
    try { bom = await fs.readFile(sbomPath, "utf8"); }
    catch { await ctx.log("warn", "SBOM not generated"); return; }
    finally { fs.rm(sbomPath, { force: true }).catch(() => {}); }

    await ctx.progress(0.45, "uploading to Dependency-Track");
    const uploadBody = projectUuid
      ? { project: projectUuid, bom: Buffer.from(bom).toString("base64") }
      : { projectName, projectVersion, autoCreate: true, bom: Buffer.from(bom).toString("base64") };
    const upload = await fetch(`${dtUrl}/api/v1/bom`, {
      method: "PUT",
      headers: { "X-Api-Key": dtKey, "Content-Type": "application/json" },
      body: JSON.stringify(uploadBody),
      signal: ctx.signal,
    });
    if (!upload.ok) { await ctx.log("error", `Dependency-Track upload failed: ${upload.status}`); return; }
    const { token } = await upload.json().catch(() => ({ token: "" }));

    // Wait for processing to complete.
    if (token) {
      for (let i = 0; i < 40 && !ctx.signal.aborted; i++) {
        const r = await fetch(`${dtUrl}/api/v1/bom/token/${token}`, { headers: { "X-Api-Key": dtKey } });
        const j = await r.json().catch(() => ({ processing: true }));
        if (!j.processing) break;
        await new Promise((r) => setTimeout(r, 2500));
        await ctx.progress(0.45 + 0.2 * (i / 40), "DT processing");
      }
    }

    // Fetch findings.
    await ctx.progress(0.7, "fetching findings");
    let findingsUrl = "";
    if (projectUuid) {
      findingsUrl = `${dtUrl}/api/v1/finding/project/${projectUuid}`;
    } else {
      // Resolve the project we just created/updated.
      const lookup = await fetch(`${dtUrl}/api/v1/project/lookup?name=${encodeURIComponent(projectName)}&version=${encodeURIComponent(projectVersion)}`, { headers: { "X-Api-Key": dtKey } });
      if (!lookup.ok) { await ctx.log("error", "DT project lookup failed"); return; }
      const proj = await lookup.json();
      findingsUrl = `${dtUrl}/api/v1/finding/project/${proj.uuid}`;
    }
    const fres = await fetch(findingsUrl, { headers: { "X-Api-Key": dtKey } });
    if (!fres.ok) return;
    const findings: Array<{ component: { name: string; version: string; purl: string }; vulnerability: { source: string; vulnId: string; title?: string; description?: string; severity?: string; cvssV3BaseScore?: number; cwe?: number; references?: string[] } }> = await fres.json();

    for (const f of findings) {
      const sev = ((f.vulnerability.severity ?? "MEDIUM").toUpperCase() as "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO");
      const map: Record<string, "critical"|"high"|"medium"|"low"|"info"> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "info" };
      await ctx.emit(draft({
        severity: map[sev] ?? "medium",
        confidence: "high",
        title: `Dependency-Track: ${f.component.name}@${f.component.version} — ${f.vulnerability.vulnId}`,
        description: f.vulnerability.title ?? f.vulnerability.description ?? "",
        ruleId: `${f.vulnerability.source}/${f.vulnerability.vulnId}`,
        cve: /^CVE-/i.test(f.vulnerability.vulnId) ? [f.vulnerability.vulnId] : undefined,
        cwe: f.vulnerability.cwe ? [`CWE-${f.vulnerability.cwe}`] : undefined,
        cvss: f.vulnerability.cvssV3BaseScore,
        location: { file: f.component.purl },
        references: f.vulnerability.references,
      }));
    }
    await ctx.progress(1, `${findings.length} DT findings`);
  },
};

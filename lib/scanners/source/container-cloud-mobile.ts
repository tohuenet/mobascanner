/**
 * Container / Cloud / Mobile adapters — wrap CLI tools and emit normalized
 * Findings. All gracefully no-op when their CLI isn't installed.
 *
 *   - source.dockle      — CIS Docker bench + image best practices
 *   - source.dive        — image-layer analysis, finds wasted space + leaks
 *   - source.hadolint    — Dockerfile linter
 *   - source.kube-bench  — CIS Kubernetes Benchmark
 *   - source.kube-hunter — penetration test for k8s clusters
 *   - source.prowler     — AWS / Azure / GCP / K8s posture (huge tool)
 *   - source.mobsf       — APK / IPA static analysis (calls MobSF API)
 */

import path from "node:path";
import { promises as fs } from "node:fs";
import os from "node:os";
import { randomUUID } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, truncate } from "../common";
import { resolveSourceTarget } from "./git-import";

const SEV_MAP: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "info",
  FATAL: "critical", ERROR: "high", WARN: "medium", IGNORE: "info",
  PASS: "info", FAIL: "high", "FAIL (HIGH)": "high", "FAIL (MEDIUM)": "medium",
};

// ───────────────────────── Dockle ─────────────────────────────
export const dockleScanner: Scanner = {
  id: "source.dockle",
  name: "Dockle (CIS Docker)",
  kind: "source",
  description: "Goodwith dockle — image security best practices + CIS Docker bench. Set `options.image` to the image tag (e.g. `nginx:latest`); falls back to scanning every Dockerfile in the source tree.",
  defaultEnabled: false,
  async tool() {
    const v = await detectCli("dockle", "--version");
    return {
      id: "source.dockle", name: "Dockle", kind: "source", backend: "cli",
      cliCommand: "dockle", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`brew install goodwithtech/r/dockle` or GitHub releases",
      upstream: "https://github.com/goodwithtech/dockle", license: "Apache-2.0",
      description: "Container image security checker.",
    };
  },
  async run(ctx) {
    const v = await detectCli("dockle", "--version");
    if (!v) { await ctx.log("warn", "dockle not found"); return; }
    const image = ctx.options.image as string;
    if (!image) { await ctx.log("info", "options.image required"); return; }
    const r = await runCli("dockle", ["-f", "json", image], { signal: ctx.signal, timeoutMs: 15 * 60 * 1000 });
    if (r.spawnError || !r.stdout.trim()) return;
    let parsed: { details?: Array<{ code: string; title: string; level: string; alerts: string[] }> };
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    for (const d of parsed.details ?? []) {
      await ctx.emit(draft({
        severity: SEV_MAP[d.level] ?? "low", confidence: "high",
        title: `dockle ${d.code}: ${d.title}`,
        description: d.alerts.join("\n"),
        ruleId: `dockle/${d.code}`,
        location: { file: image },
        evidence: { code: d.code, level: d.level, alerts: d.alerts.slice(0, 5) },
      }));
    }
    await ctx.progress(1, `${(parsed.details ?? []).length} dockle findings`);
  },
};

// ───────────────────────── Hadolint ────────────────────────────
export const hadolintScanner: Scanner = {
  id: "source.hadolint",
  name: "Hadolint (Dockerfile)",
  kind: "source",
  description: "Hadolint — Dockerfile best-practice linter. Walks the source tree, runs hadolint on every Dockerfile.",
  defaultEnabled: false,
  async tool() {
    const v = await detectCli("hadolint", "--version");
    return {
      id: "source.hadolint", name: "Hadolint", kind: "source", backend: "cli",
      cliCommand: "hadolint", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`brew install hadolint` / GitHub releases",
      upstream: "https://github.com/hadolint/hadolint", license: "GPL-3.0",
      description: "Dockerfile linter.",
    };
  },
  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    const v = await detectCli("hadolint", "--version");
    if (!v) { await ctx.log("warn", "hadolint not found"); return; }
    // Find every Dockerfile.
    const candidates: string[] = [];
    async function walk(d: string) {
      let entries; try { entries = await fs.readdir(d, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (e.name === "node_modules" || e.name === ".git") continue;
        const full = path.join(d, e.name);
        if (e.isDirectory()) await walk(full);
        else if (/^Dockerfile\b/i.test(e.name) || /\.dockerfile$/i.test(e.name)) candidates.push(full);
      }
    }
    await walk(root);
    let n = 0;
    for (const file of candidates) {
      if (ctx.signal.aborted) break;
      const r = await runCli("hadolint", ["-f", "json", file], { signal: ctx.signal, timeoutMs: 60_000 });
      if (!r.stdout.trim()) continue;
      let parsed: Array<{ code: string; line: number; level: string; message: string }>;
      try { parsed = JSON.parse(r.stdout); } catch { continue; }
      for (const item of parsed) {
        n += 1;
        await ctx.emit(draft({
          severity: SEV_MAP[item.level.toUpperCase()] ?? "low", confidence: "high",
          title: `hadolint ${item.code}: ${item.message}`,
          description: `Dockerfile linter: ${item.message}`,
          ruleId: `hadolint/${item.code}`,
          location: { file: path.relative(root, file).replace(/\\/g, "/"), line: item.line },
        }));
      }
    }
    await ctx.progress(1, `${n} hadolint findings across ${candidates.length} Dockerfile(s)`);
  },
};

// ───────────────────────── kube-bench ────────────────────────────
export const kubeBenchScanner: Scanner = {
  id: "source.kube-bench",
  name: "kube-bench (CIS Kubernetes)",
  kind: "source",
  description: "Aqua's kube-bench — CIS Kubernetes Benchmark checks. Run from inside a cluster node OR with `options.targets=master,node,etcd`.",
  defaultEnabled: false,
  async tool() {
    const v = await detectCli("kube-bench", "--version");
    return {
      id: "source.kube-bench", name: "kube-bench", kind: "source", backend: "cli",
      cliCommand: "kube-bench", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`brew install kube-bench` / Aqua releases",
      upstream: "https://github.com/aquasecurity/kube-bench", license: "Apache-2.0",
      description: "CIS Kubernetes Benchmark scanner.",
    };
  },
  async run(ctx) {
    const v = await detectCli("kube-bench", "--version");
    if (!v) { await ctx.log("warn", "kube-bench not found"); return; }
    const args = ["run", "--json"];
    if (ctx.options.targets) args.push("--targets", String(ctx.options.targets));
    const r = await runCli("kube-bench", args, { signal: ctx.signal, timeoutMs: 15 * 60 * 1000 });
    if (r.spawnError || !r.stdout.trim()) return;
    let parsed: { Controls?: Array<{ tests?: Array<{ section: string; results?: Array<{ test_number: string; test_desc: string; status: string; remediation?: string }> }> }> };
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    for (const c of parsed.Controls ?? []) {
      for (const t of c.tests ?? []) {
        for (const res of t.results ?? []) {
          if (res.status === "PASS") continue;
          await ctx.emit(draft({
            severity: res.status === "FAIL" ? "medium" : "low", confidence: "high",
            title: `kube-bench ${res.test_number}: ${res.test_desc}`,
            description: res.test_desc,
            ruleId: `kube-bench/${res.test_number}`,
            location: { file: t.section },
            evidence: { status: res.status },
            remediation: res.remediation,
          }));
        }
      }
    }
    await ctx.progress(1, "kube-bench done");
  },
};

// ───────────────────────── kube-hunter ────────────────────────────
export const kubeHunterScanner: Scanner = {
  id: "source.kube-hunter",
  name: "kube-hunter",
  kind: "source",
  description: "Aqua's kube-hunter — active penetration test for k8s clusters. Use `options.remote=cluster.example.com` to scan from outside the cluster.",
  defaultEnabled: false,
  async tool() {
    const v = await detectCli("kube-hunter", "--help");
    return {
      id: "source.kube-hunter", name: "kube-hunter", kind: "source", backend: "cli",
      cliCommand: "kube-hunter", cliVersionArg: "--help",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`pip install kube-hunter` / Aqua image",
      upstream: "https://github.com/aquasecurity/kube-hunter", license: "Apache-2.0",
      description: "Kubernetes pentest tool.",
    };
  },
  async run(ctx) {
    const v = await detectCli("kube-hunter", "--help");
    if (!v) return;
    const args = ["--report", "json"];
    if (ctx.options.remote) args.push("--remote", String(ctx.options.remote));
    else args.push("--pod");
    const r = await runCli("kube-hunter", args, { signal: ctx.signal, timeoutMs: 15 * 60 * 1000 });
    if (!r.stdout.trim()) return;
    let parsed: { vulnerabilities?: Array<{ vid?: string; severity: string; vulnerability: string; description: string; location: string; evidence?: string; hunter?: string }> };
    try { parsed = JSON.parse(r.stdout); } catch { return; }
    for (const v2 of parsed.vulnerabilities ?? []) {
      await ctx.emit(draft({
        severity: SEV_MAP[v2.severity.toUpperCase()] ?? "medium", confidence: "high",
        title: `kube-hunter: ${v2.vulnerability}`,
        description: v2.description,
        ruleId: `kube-hunter/${v2.vid ?? v2.vulnerability.replace(/\s+/g, "-").toLowerCase()}`,
        location: { url: v2.location },
        evidence: { hunter: v2.hunter, evidence: v2.evidence },
      }));
    }
    await ctx.progress(1, `${(parsed.vulnerabilities ?? []).length} kube-hunter findings`);
  },
};

// ───────────────────────── Prowler ────────────────────────────
export const prowlerScanner: Scanner = {
  id: "source.prowler",
  name: "Prowler (AWS/Azure/GCP/K8s posture)",
  kind: "source",
  description: "Prowler v3 — multi-cloud security posture audit. Set `options.provider=aws|azure|gcp|kubernetes`. Inherits the CLI's auth (env / IAM / kubeconfig).",
  defaultEnabled: false,
  async tool() {
    const v = await detectCli("prowler", "--version");
    return {
      id: "source.prowler", name: "Prowler", kind: "source", backend: "cli",
      cliCommand: "prowler", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`pip install prowler` / Docker image",
      upstream: "https://github.com/prowler-cloud/prowler", license: "Apache-2.0",
      description: "Multi-cloud + Kubernetes posture audit.",
    };
  },
  async run(ctx) {
    const v = await detectCli("prowler", "--version");
    if (!v) return;
    const provider = (ctx.options.provider as string) ?? "aws";
    const out = path.join(os.tmpdir(), `prowler-${randomUUID()}`);
    const r = await runCli("prowler", [provider, "-M", "json-asff", "-o", out, "--quiet"], { signal: ctx.signal, timeoutMs: 60 * 60 * 1000 });
    if (r.spawnError) return;
    // Prowler writes <out>/prowler-output-<acct>-<region>.asff.json
    let entries; try { entries = await fs.readdir(out); } catch { return; }
    for (const f of entries) {
      if (!f.endsWith(".json")) continue;
      let parsed; try { parsed = JSON.parse(await fs.readFile(path.join(out, f), "utf8")); } catch { continue; }
      for (const item of (parsed.Findings ?? parsed) as Array<{ Severity?: { Label?: string }; Title?: string; Description?: string; Resources?: Array<{ Id?: string }>; ProductFields?: { CheckId?: string }; Remediation?: { Recommendation?: { Text?: string } } }>) {
        await ctx.emit(draft({
          severity: SEV_MAP[item.Severity?.Label ?? "MEDIUM"] ?? "medium", confidence: "high",
          title: `prowler: ${item.Title ?? "(unnamed)"}`,
          description: item.Description ?? "",
          ruleId: `prowler/${item.ProductFields?.CheckId ?? "unknown"}`,
          location: { file: item.Resources?.[0]?.Id ?? provider },
          remediation: item.Remediation?.Recommendation?.Text,
        }));
      }
    }
    fs.rm(out, { recursive: true, force: true }).catch(() => {});
    await ctx.progress(1, "prowler done");
  },
};

// ───────────────────────── MobSF ────────────────────────────
export const mobsfScanner: Scanner = {
  id: "source.mobsf",
  name: "MobSF (mobile static analysis)",
  kind: "source",
  description: "Mobile Security Framework — static analysis for APK / IPA. Calls a running MobSF instance. Set `options.mobsfUrl`, `options.apiKey`, `options.file=<path-to-apk>`.",
  defaultEnabled: false,
  async tool() {
    return {
      id: "source.mobsf", name: "MobSF", kind: "source", backend: "api", status: "unknown",
      installHint: "`docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf`",
      upstream: "https://github.com/MobSF/Mobile-Security-Framework-MobSF", license: "GPL-3.0",
      description: "Mobile (Android/iOS) static + dynamic analysis suite.",
    };
  },
  async run(ctx) {
    const mobsfUrl = (ctx.options.mobsfUrl as string)?.replace(/\/$/, "");
    const apiKey = ctx.options.apiKey as string;
    const file = ctx.options.file as string;
    if (!mobsfUrl || !apiKey || !file) { await ctx.log("warn", "options.mobsfUrl, apiKey, file required"); return; }
    let stat; try { stat = await fs.stat(file); } catch { await ctx.log("error", `file not found: ${file}`); return; }
    // Upload.
    const buf = await fs.readFile(file);
    const boundary = "------MobaMobSF" + randomUUID();
    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${path.basename(file)}"\r\nContent-Type: application/octet-stream\r\n\r\n`),
      buf,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    const upload = await fetch(`${mobsfUrl}/api/v1/upload`, {
      method: "POST",
      headers: { Authorization: apiKey, "Content-Type": `multipart/form-data; boundary=${boundary}` },
      body, signal: ctx.signal,
    });
    if (!upload.ok) { await ctx.log("error", `MobSF upload failed: ${upload.status}`); return; }
    const meta = await upload.json() as { hash: string; scan_type: string };
    // Trigger static analysis.
    const scan = await fetch(`${mobsfUrl}/api/v1/scan`, {
      method: "POST", headers: { Authorization: apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ hash: meta.hash, scan_type: meta.scan_type, file_name: path.basename(file) }).toString(),
      signal: ctx.signal,
    });
    if (!scan.ok) return;
    // Pull report.
    const report = await fetch(`${mobsfUrl}/api/v1/report_json`, {
      method: "POST", headers: { Authorization: apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ hash: meta.hash }).toString(), signal: ctx.signal,
    });
    if (!report.ok) return;
    const j = await report.json() as { permissions?: Record<string, { status: string; description: string }>; manifest_analysis?: Array<{ rule: string; description: string; severity: string }>; code_analysis?: Record<string, { metadata: { description: string; severity: string }; files: string[] }> };
    let n = 0;
    for (const m of j.manifest_analysis ?? []) {
      n++;
      await ctx.emit(draft({
        severity: SEV_MAP[m.severity.toUpperCase()] ?? "medium", confidence: "high",
        title: `MobSF manifest: ${m.rule}`,
        description: m.description,
        ruleId: `mobsf/manifest/${m.rule}`,
        location: { file: file },
      }));
    }
    for (const [rule, info] of Object.entries(j.code_analysis ?? {})) {
      n++;
      await ctx.emit(draft({
        severity: SEV_MAP[info.metadata.severity.toUpperCase()] ?? "medium", confidence: "medium",
        title: `MobSF code: ${rule}`,
        description: info.metadata.description,
        ruleId: `mobsf/code/${rule}`,
        location: { file: info.files?.[0] ?? file },
        evidence: { affectedFiles: info.files?.slice(0, 5) },
      }));
    }
    await ctx.progress(1, `${n} MobSF findings`);
  },
};

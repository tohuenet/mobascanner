/**
 * External CLI adapters consolidated:
 *
 *   - ffuf      → content discovery (large wordlist scan)
 *   - zap-api   → OWASP ZAP daemon (full DAST: passive + active)
 *   - wapiti    → web vuln scanner (XSS / SQLi / LFI / etc.)
 *   - nikto     → legacy web server scanner (config issues)
 *   - sqlmap    → automated SQLi exploitation tester
 *
 * Each adapter is a thin wrapper that:
 *   1. Detects the binary at scan time and `skips` gracefully if missing.
 *   2. Streams or post-processes the tool's JSON output where supported.
 *   3. Maps fields to our normalized Finding shape.
 *
 * For tools without JSON output (nikto, sqlmap classic), we rely on the
 * `-oJ` / `--output-format=json` flag where available, otherwise we parse
 * line-by-line markers.
 */

import path from "node:path";
import os from "node:os";
import { promises as fs } from "node:fs";
import { randomUUID } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, safeUrl, truncate } from "../common";

// ───────────────────────────── ffuf ─────────────────────────────
export const ffufScanner: Scanner = {
  id: "web.ffuf",
  name: "ffuf",
  kind: "web",
  description: "Massive content discovery via ffuf. Default wordlist: SecLists Discovery/Web-Content/raft-medium-words.txt (configure via options.wordlist).",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("ffuf", "-V");
    return {
      id: "web.ffuf", name: "ffuf", kind: "web", backend: "cli",
      cliCommand: "ffuf", cliVersionArg: "-V",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`go install github.com/ffuf/ffuf/v2@latest` or GitHub releases",
      upstream: "https://github.com/ffuf/ffuf",
      license: "MIT",
      description: "Fast web fuzzer — content / parameter discovery.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("ffuf", "-V");
    if (!v) { await ctx.log("warn", "ffuf not found"); return; }
    const wordlist = (ctx.options.wordlist as string) || "";
    if (!wordlist) { await ctx.log("warn", "options.wordlist required for ffuf — skipping"); return; }

    const out = path.join(os.tmpdir(), `ffuf-${randomUUID()}.json`);
    const args = ["-u", `${url.origin}/FUZZ`, "-w", wordlist, "-mc", "200,201,204,301,302,307,401,403", "-of", "json", "-o", out, "-s"];
    await ctx.log("info", `ffuf ${v}`);
    const r = await runCli("ffuf", args, { signal: ctx.signal, timeoutMs: 60 * 60 * 1000 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }

    let parsed: { results?: Array<{ url: string; status: number; length: number; words: number }> };
    try { parsed = JSON.parse(await fs.readFile(out, "utf8")); }
    catch { return; }
    finally { fs.rm(out, { force: true }).catch(() => {}); }

    for (const res of parsed.results ?? []) {
      await ctx.emit(draft({
        severity: res.status === 200 ? "low" : "info",
        confidence: "medium",
        title: `ffuf: ${res.url} (${res.status})`,
        description: `ffuf discovered a reachable path returning HTTP ${res.status}.`,
        ruleId: "ffuf/discovered",
        cwe: ["CWE-538"],
        owasp: ["A05:2021"],
        location: { url: res.url },
        evidence: { status: res.status, length: res.length, words: res.words },
      }));
    }
    await ctx.progress(1, `${(parsed.results ?? []).length} hits`);
  },
};

// ───────────────────────────── ZAP ──────────────────────────────
// ZAP is a full Java daemon. We don't run it as a CLI — we talk to its REST API.
// The user is expected to start ZAP with `zap.sh -daemon -port 8090 -config api.disablekey=true`
// (or similar) and pass the base URL via options.zapBase.
interface ZapAlert { name: string; risk: string; confidence: string; description?: string; solution?: string; reference?: string; cweid?: string; wascid?: string; url: string; param?: string; evidence?: string }

export const zapApiScanner: Scanner = {
  id: "web.zap",
  name: "OWASP ZAP (API)",
  kind: "web",
  description: "Drives a running OWASP ZAP daemon over its REST API to run a passive + active scan and import alerts. Configure with options.zapBase + options.apiKey.",
  defaultEnabled: false,

  async tool() {
    return {
      id: "web.zap", name: "OWASP ZAP", kind: "web", backend: "api",
      status: "unknown",
      installHint: "Run `zap.sh -daemon -port 8090 -config api.disablekey=true` then pass options.zapBase=http://localhost:8090",
      upstream: "https://www.zaproxy.org",
      license: "Apache-2.0",
      description: "Full DAST tool by OWASP — passive + active scan rules, fuzzing, scripting.",
    };
  },

  async run(ctx) {
    const base = ((ctx.options.zapBase as string) || "http://localhost:8090").replace(/\/$/, "");
    const apiKey = (ctx.options.apiKey as string) || "";
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const qs = (extra: Record<string, string>) => new URLSearchParams({ ...(apiKey ? { apikey: apiKey } : {}), ...extra }).toString();

    // Health check
    try {
      const r = await fetch(`${base}/JSON/core/view/version/?${qs({})}`);
      if (!r.ok) throw new Error(`status ${r.status}`);
      const j = await r.json();
      await ctx.log("info", `ZAP ${j.version} reachable at ${base}`);
    } catch (e) {
      await ctx.log("warn", `ZAP daemon unreachable at ${base} — ${e instanceof Error ? e.message : e}`);
      return;
    }

    // Spider
    await ctx.progress(0.1, "ZAP spider");
    let spiderId = "";
    try {
      const r = await fetch(`${base}/JSON/spider/action/scan/?${qs({ url: url.toString() })}`);
      const j = await r.json();
      spiderId = j.scan;
    } catch { /* tolerate */ }
    if (spiderId) {
      while (!ctx.signal.aborted) {
        const s = await fetch(`${base}/JSON/spider/view/status/?${qs({ scanId: spiderId })}`).then((x) => x.json()).catch(() => ({ status: "100" }));
        const pct = Number(s.status ?? 100);
        await ctx.progress(0.1 + 0.3 * (pct / 100), `spider ${pct}%`);
        if (pct >= 100) break;
        await new Promise((r) => setTimeout(r, 1500));
      }
    }

    // Active scan
    await ctx.progress(0.45, "ZAP active scan");
    let ascanId = "";
    try {
      const r = await fetch(`${base}/JSON/ascan/action/scan/?${qs({ url: url.toString() })}`);
      const j = await r.json();
      ascanId = j.scan;
    } catch { /* tolerate */ }
    if (ascanId) {
      while (!ctx.signal.aborted) {
        const s = await fetch(`${base}/JSON/ascan/view/status/?${qs({ scanId: ascanId })}`).then((x) => x.json()).catch(() => ({ status: "100" }));
        const pct = Number(s.status ?? 100);
        await ctx.progress(0.45 + 0.45 * (pct / 100), `active scan ${pct}%`);
        if (pct >= 100) break;
        await new Promise((r) => setTimeout(r, 2500));
      }
    }

    // Alerts
    await ctx.progress(0.95, "fetching alerts");
    const alertsRes = await fetch(`${base}/JSON/core/view/alerts/?${qs({ baseurl: url.toString() })}`).catch(() => null);
    if (!alertsRes || !alertsRes.ok) { await ctx.log("warn", "could not fetch ZAP alerts"); return; }
    const alerts: ZapAlert[] = (await alertsRes.json()).alerts ?? [];

    const sevMap: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
      High: "high", Medium: "medium", Low: "low", Informational: "info",
    };
    for (const a of alerts) {
      await ctx.emit(draft({
        severity: sevMap[a.risk] ?? "info",
        confidence: a.confidence === "High" ? "high" : a.confidence === "Medium" ? "medium" : "low",
        title: `ZAP: ${a.name}`,
        description: a.description ?? "",
        ruleId: `zap/${a.name.replace(/\s+/g, "-").toLowerCase()}`,
        cwe: a.cweid ? [`CWE-${a.cweid}`] : undefined,
        location: { url: a.url, snippet: a.param },
        evidence: a.evidence ? { evidence: truncate(a.evidence, 400), wasc: a.wascid } : { wasc: a.wascid },
        remediation: a.solution,
        references: a.reference ? [a.reference] : undefined,
      }));
    }
    await ctx.progress(1, `${alerts.length} ZAP alerts`);
  },
};

// ───────────────────────────── wapiti ───────────────────────────
export const wapitiScanner: Scanner = {
  id: "web.wapiti",
  name: "wapiti",
  kind: "web",
  description: "Wapiti web vulnerability scanner — XSS, SQLi, file inclusion, command exec, weak cookies, etc.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("wapiti", "--version");
    return {
      id: "web.wapiti", name: "wapiti", kind: "web", backend: "cli",
      cliCommand: "wapiti", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`pip install wapiti3`",
      upstream: "https://github.com/wapiti-scanner/wapiti",
      license: "GPL-2.0",
      description: "Active web vulnerability scanner.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("wapiti", "--version");
    if (!v) { await ctx.log("warn", "wapiti not found"); return; }
    const out = path.join(os.tmpdir(), `wapiti-${randomUUID()}.json`);
    const args = ["-u", url.toString(), "-f", "json", "-o", out, "--flush-session", "-S", "normal"];
    await ctx.log("info", `wapiti ${v}`);
    const r = await runCli("wapiti", args, { signal: ctx.signal, timeoutMs: 60 * 60 * 1000 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    let parsed: { vulnerabilities?: Record<string, Array<{ method: string; path: string; info: string; level: number }>> };
    try { parsed = JSON.parse(await fs.readFile(out, "utf8")); }
    catch { return; }
    finally { fs.rm(out, { force: true }).catch(() => {}); }

    const sevMap: Record<number, "critical" | "high" | "medium" | "low" | "info"> = { 4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info" };
    let count = 0;
    for (const [category, items] of Object.entries(parsed.vulnerabilities ?? {})) {
      for (const item of items) {
        count += 1;
        await ctx.emit(draft({
          severity: sevMap[item.level ?? 1] ?? "low",
          confidence: "medium",
          title: `wapiti: ${category}`,
          description: item.info,
          ruleId: `wapiti/${category}`,
          location: { url: new URL(item.path, url).toString(), snippet: item.method },
        }));
      }
    }
    await ctx.progress(1, `${count} wapiti findings`);
  },
};

// ───────────────────────────── nikto ────────────────────────────
export const niktoScanner: Scanner = {
  id: "web.nikto",
  name: "nikto",
  kind: "web",
  description: "Legacy web server scanner — outdated software, default files, misconfigured headers, ~6700 known issues.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("nikto", "-Version");
    return {
      id: "web.nikto", name: "nikto", kind: "web", backend: "cli",
      cliCommand: "nikto", cliVersionArg: "-Version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`brew install nikto` / `apt install nikto` / `git clone https://github.com/sullo/nikto`",
      upstream: "https://github.com/sullo/nikto",
      license: "GPL-2.0",
      description: "Web server scanner with 6700+ checks.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("nikto", "-Version");
    if (!v) { await ctx.log("warn", "nikto not found"); return; }
    const out = path.join(os.tmpdir(), `nikto-${randomUUID()}.json`);
    const args = ["-h", url.toString(), "-Format", "json", "-output", out, "-ask", "no", "-nointeractive"];
    await ctx.log("info", `nikto ${v}`);
    const r = await runCli("nikto", args, { signal: ctx.signal, timeoutMs: 30 * 60 * 1000 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    let parsed: { vulnerabilities?: Array<{ id: string; method: string; url: string; msg: string }> };
    try { parsed = JSON.parse(await fs.readFile(out, "utf8")); }
    catch { return; }
    finally { fs.rm(out, { force: true }).catch(() => {}); }
    for (const v2 of parsed.vulnerabilities ?? []) {
      await ctx.emit(draft({
        severity: "medium",
        confidence: "medium",
        title: `nikto: ${v2.msg.split(":")[0].slice(0, 100)}`,
        description: v2.msg,
        ruleId: `nikto/${v2.id}`,
        location: { url: v2.url ? new URL(v2.url, url).toString() : url.toString(), snippet: v2.method },
      }));
    }
    await ctx.progress(1, `${(parsed.vulnerabilities ?? []).length} nikto findings`);
  },
};

// ───────────────────────────── sqlmap ───────────────────────────
export const sqlmapScanner: Scanner = {
  id: "web.sqlmap",
  name: "sqlmap",
  kind: "web",
  description: "Automated SQL-injection tester. Runs in non-interactive mode against URLs with query parameters.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("sqlmap", "--version");
    return {
      id: "web.sqlmap", name: "sqlmap", kind: "web", backend: "cli",
      cliCommand: "sqlmap", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`pip install sqlmap` / `git clone https://github.com/sqlmapproject/sqlmap`",
      upstream: "https://github.com/sqlmapproject/sqlmap",
      license: "GPL-2.0",
      description: "Automated SQLi detection / exploitation. Aggressive — only run on authorized targets.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    if (![...url.searchParams.keys()].length) { await ctx.log("info", "no query params — sqlmap skipped"); return; }
    const v = await detectCli("sqlmap", "--version");
    if (!v) { await ctx.log("warn", "sqlmap not found"); return; }
    const out = path.join(os.tmpdir(), `sqlmap-${randomUUID()}.json`);
    const args = ["-u", url.toString(), "--batch", "--output-dir", path.dirname(out), "--results-file", out, "--level", "1", "--risk", "1"];
    await ctx.log("info", `sqlmap ${v}`);
    const r = await runCli("sqlmap", args, { signal: ctx.signal, timeoutMs: 30 * 60 * 1000 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    // sqlmap's results-file is CSV; parse minimally.
    let txt: string;
    try { txt = await fs.readFile(out, "utf8"); } catch { return; }
    finally { fs.rm(out, { force: true }).catch(() => {}); }
    const lines = txt.split(/\r?\n/).slice(1).filter(Boolean);
    for (const line of lines) {
      const cols = line.split(",");
      const target = cols[0];
      const param = cols[1];
      if (!target || !param) continue;
      await ctx.emit(draft({
        severity: "critical",
        confidence: "high",
        title: `sqlmap: SQL injection on parameter "${param}"`,
        description: `sqlmap confirmed SQL injection on ${target} via parameter ${param}.`,
        ruleId: "sqlmap/confirmed",
        cwe: ["CWE-89"],
        owasp: ["A03:2021"],
        location: { url: target, snippet: param },
        remediation: "Use parameterized queries / prepared statements. Audit every ORM raw-SQL usage.",
      }));
    }
    await ctx.progress(1, `${lines.length} confirmed`);
  },
};

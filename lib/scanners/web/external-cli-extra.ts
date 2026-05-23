/**
 * Additional external-CLI web adapters:
 *
 *   - testssl  → deep TLS / cipher / vulnerability survey
 *   - subfinder → ProjectDiscovery passive subdomain enum
 *   - httpx     → ProjectDiscovery URL probe / fingerprint
 *   - katana    → ProjectDiscovery JS-aware crawler
 *   - naabu     → ProjectDiscovery fast SYN/CONNECT port scanner
 *   - masscan   → world's-fastest port scanner (root-only on linux)
 *   - dastardly → PortSwigger's free DAST CLI (runs Burp scan engine)
 *
 * Each adapter detects its binary at scan time and skips gracefully if
 * missing. JSON output is preferred so we can feed the normalized Finding
 * pipeline directly.
 */

import path from "node:path";
import os from "node:os";
import { promises as fs } from "node:fs";
import { randomUUID } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, safeUrl, truncate } from "../common";

// ───────────────────────── testssl.sh ───────────────────────────
interface TestsslEntry { id: string; severity: string; finding: string; ip?: string; port?: string; cve?: string; cwe?: string }
const TESTSSL_SEV: Record<string, "critical"|"high"|"medium"|"low"|"info"> = {
  CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", WARN: "low", INFO: "info", OK: "info", DEBUG: "info",
};

export const testsslScanner: Scanner = {
  id: "web.testssl",
  name: "testssl.sh",
  kind: "web",
  description: "Drew Heinrich's testssl.sh — deep TLS audit (CVE checks, weak ciphers, FREAK/POODLE/Heartbleed/ROBOT/etc.).",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("testssl.sh", "--version");
    return {
      id: "web.testssl", name: "testssl.sh", kind: "web", backend: "cli",
      cliCommand: "testssl.sh", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`brew install testssl` / `git clone https://github.com/drwetter/testssl.sh`",
      upstream: "https://github.com/drwetter/testssl.sh",
      license: "GPL-2.0",
      description: "Industry-standard deep TLS / cipher audit.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("testssl.sh", "--version");
    if (!v) { await ctx.log("warn", "testssl.sh not found"); return; }

    const out = path.join(os.tmpdir(), `testssl-${randomUUID()}.json`);
    const args = ["--quiet", "--color", "0", "--jsonfile", out, "--severity", "LOW", url.host];
    await ctx.log("info", `testssl.sh ${v}`);
    const r = await runCli("testssl.sh", args, { signal: ctx.signal, timeoutMs: 30 * 60 * 1000 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }

    let entries: TestsslEntry[] = [];
    try { entries = JSON.parse(await fs.readFile(out, "utf8")); }
    catch { return; }
    finally { fs.rm(out, { force: true }).catch(() => {}); }

    let n = 0;
    for (const e of entries) {
      const sev = TESTSSL_SEV[(e.severity ?? "INFO").toUpperCase()] ?? "info";
      if (sev === "info") continue; // skip OK/DEBUG noise
      n += 1;
      await ctx.emit(draft({
        severity: sev,
        confidence: "high",
        title: `testssl: ${e.id} — ${e.finding.slice(0, 120)}`,
        description: e.finding,
        ruleId: `testssl/${e.id}`,
        cve: e.cve ? [e.cve] : undefined,
        cwe: e.cwe ? [`CWE-${e.cwe}`] : undefined,
        location: { url: `${e.ip ?? url.host}:${e.port ?? 443}` },
      }));
    }
    await ctx.progress(1, `${n} testssl findings`);
  },
};

// ──────────────────────── subfinder ─────────────────────────────
export const subfinderScanner: Scanner = {
  id: "web.subfinder",
  name: "subfinder",
  kind: "web",
  description: "ProjectDiscovery passive subdomain enumeration — queries dozens of public sources (CT logs, search engines, DNS DB).",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("subfinder", "-version");
    return {
      id: "web.subfinder", name: "subfinder", kind: "web", backend: "cli",
      cliCommand: "subfinder", cliVersionArg: "-version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`",
      upstream: "https://github.com/projectdiscovery/subfinder",
      license: "MIT",
      description: "Passive subdomain enumeration.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("subfinder", "-version");
    if (!v) { await ctx.log("warn", "subfinder not found"); return; }
    const r = await runCli("subfinder", ["-d", url.hostname, "-silent", "-json"], {
      signal: ctx.signal, timeoutMs: 10 * 60 * 1000,
    });
    if (r.spawnError) return;
    let count = 0;
    for (const line of r.stdout.split(/\r?\n/)) {
      const t = line.trim();
      if (!t.startsWith("{")) continue;
      try {
        const obj = JSON.parse(t) as { host?: string; source?: string };
        if (!obj.host) continue;
        count += 1;
        await ctx.emit(draft({
          severity: "info", confidence: "high",
          title: `subfinder: ${obj.host}`,
          description: `Discovered subdomain via passive source: ${obj.source ?? "?"}`,
          ruleId: "subfinder/discovered",
          location: { url: `https://${obj.host}/` },
          evidence: { source: obj.source },
        }));
      } catch { /* ignore */ }
    }
    await ctx.progress(1, `${count} subdomains`);
  },
};

// ──────────────────────────── httpx ──────────────────────────────
export const httpxScanner: Scanner = {
  id: "web.httpx",
  name: "httpx",
  kind: "web",
  description: "ProjectDiscovery httpx — probes URLs for status, title, tech stack, TLS info. Pairs well with subfinder/katana output.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("httpx", "-version");
    return {
      id: "web.httpx", name: "httpx", kind: "web", backend: "cli",
      cliCommand: "httpx", cliVersionArg: "-version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`go install github.com/projectdiscovery/httpx/cmd/httpx@latest`",
      upstream: "https://github.com/projectdiscovery/httpx",
      license: "MIT",
      description: "HTTP toolkit / probe.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("httpx", "-version");
    if (!v) { await ctx.log("warn", "httpx not found"); return; }
    const r = await runCli("httpx", ["-u", url.toString(), "-json", "-silent", "-tech-detect", "-status-code", "-title", "-tls-grab"], {
      signal: ctx.signal, timeoutMs: 5 * 60 * 1000,
    });
    if (r.spawnError) return;
    for (const line of r.stdout.split(/\r?\n/)) {
      const t = line.trim();
      if (!t.startsWith("{")) continue;
      try {
        const obj = JSON.parse(t) as Record<string, unknown> & { url?: string; tech?: string[]; title?: string; status_code?: number };
        await ctx.emit(draft({
          severity: "info", confidence: "high",
          title: `httpx: ${obj.url} ${obj.status_code ?? ""}${obj.title ? ` — ${obj.title}` : ""}`,
          description: `Probe metadata for ${obj.url}.`,
          ruleId: "httpx/probe",
          location: { url: obj.url ?? url.toString() },
          evidence: { tech: obj.tech, status: obj.status_code, title: obj.title, tls: obj.tls },
        }));
      } catch { /* ignore */ }
    }
    await ctx.progress(1, "done");
  },
};

// ─────────────────────────── katana ──────────────────────────────
export const katanaScanner: Scanner = {
  id: "web.katana",
  name: "katana",
  kind: "web",
  description: "ProjectDiscovery katana — JS-aware crawler that follows DOM/SPA routes invisible to regex parsers.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("katana", "-version");
    return {
      id: "web.katana", name: "katana", kind: "web", backend: "cli",
      cliCommand: "katana", cliVersionArg: "-version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`go install github.com/projectdiscovery/katana/cmd/katana@latest`",
      upstream: "https://github.com/projectdiscovery/katana",
      license: "MIT",
      description: "JS-aware web crawler.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("katana", "-version");
    if (!v) { await ctx.log("warn", "katana not found"); return; }
    const r = await runCli("katana", ["-u", url.toString(), "-jsonl", "-silent", "-d", String(ctx.options.depth ?? 3), "-jc"], {
      signal: ctx.signal, timeoutMs: 15 * 60 * 1000, maxBufferBytes: 64 * 1024 * 1024,
    });
    if (r.spawnError) return;
    const seen = new Set<string>();
    for (const line of r.stdout.split(/\r?\n/)) {
      const t = line.trim();
      if (!t.startsWith("{")) continue;
      try {
        const obj = JSON.parse(t) as { request?: { endpoint?: string; method?: string; url?: string } };
        const u = obj.request?.endpoint ?? obj.request?.url;
        if (!u || seen.has(u)) continue;
        seen.add(u);
      } catch { /* ignore */ }
    }
    if (seen.size) {
      await ctx.emit(draft({
        severity: "info", confidence: "high",
        title: `katana enumerated ${seen.size} URL(s)`,
        description: "JS-aware crawl inventory — feeds the active-injection scanner with extra parameter surface.",
        ruleId: "katana/inventory",
        location: { url: url.toString() },
        evidence: { discovered: [...seen].slice(0, 200) },
      }));
    }
    await ctx.progress(1, `${seen.size} URLs`);
  },
};

// ──────────────────────────── naabu ──────────────────────────────
export const naabuScanner: Scanner = {
  id: "web.naabu",
  name: "naabu",
  kind: "web",
  description: "ProjectDiscovery naabu — fast SYN/CONNECT port scanner. Alternative to nmap when speed matters more than service detection.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("naabu", "-version");
    return {
      id: "web.naabu", name: "naabu", kind: "web", backend: "cli",
      cliCommand: "naabu", cliVersionArg: "-version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`",
      upstream: "https://github.com/projectdiscovery/naabu",
      license: "MIT",
      description: "Fast port scanner.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("naabu", "-version");
    if (!v) { await ctx.log("warn", "naabu not found"); return; }
    const r = await runCli("naabu", ["-host", url.hostname, "-json", "-silent", "-top-ports", String(ctx.options.topPorts ?? 1000)], {
      signal: ctx.signal, timeoutMs: 10 * 60 * 1000,
    });
    if (r.spawnError) return;
    let n = 0;
    for (const line of r.stdout.split(/\r?\n/)) {
      const t = line.trim();
      if (!t.startsWith("{")) continue;
      try {
        const obj = JSON.parse(t) as { host?: string; port?: number };
        if (!obj.port) continue;
        n += 1;
        await ctx.emit(draft({
          severity: "info", confidence: "high",
          title: `naabu: ${obj.host}:${obj.port}/tcp open`,
          description: "naabu detected an open TCP port.",
          ruleId: "naabu/open-port",
          location: { url: `${obj.host}:${obj.port}` },
        }));
      } catch { /* ignore */ }
    }
    await ctx.progress(1, `${n} open ports`);
  },
};

// ─────────────────────────── masscan ─────────────────────────────
export const masscanScanner: Scanner = {
  id: "web.masscan",
  name: "masscan",
  kind: "web",
  description: "Robert Graham's masscan — internet-scale TCP port scan. Requires raw-socket privileges (root/CAP_NET_RAW).",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("masscan", "--version");
    return {
      id: "web.masscan", name: "masscan", kind: "web", backend: "cli",
      cliCommand: "masscan", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`brew install masscan` / `apt install masscan`. Run as root for raw sockets.",
      upstream: "https://github.com/robertdavidgraham/masscan",
      license: "AGPL-3.0",
      description: "Internet-scale port scanner (raw-socket).",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("masscan", "--version");
    if (!v) { await ctx.log("warn", "masscan not found"); return; }
    const out = path.join(os.tmpdir(), `masscan-${randomUUID()}.json`);
    const ports = (ctx.options.ports as string) || "1-1024,3306,5432,6379,8080,8443,9200,27017";
    const rate = String(ctx.options.rate ?? 1000);
    const r = await runCli("masscan", [url.hostname, "-p", ports, "--rate", rate, "-oJ", out], {
      signal: ctx.signal, timeoutMs: 30 * 60 * 1000,
    });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    let parsed: Array<{ ip: string; ports: Array<{ port: number; status: string; reason: string }> }>;
    try { parsed = JSON.parse(await fs.readFile(out, "utf8")); }
    catch { return; }
    finally { fs.rm(out, { force: true }).catch(() => {}); }
    let n = 0;
    for (const host of parsed) {
      for (const p of host.ports ?? []) {
        if (p.status !== "open") continue;
        n += 1;
        await ctx.emit(draft({
          severity: "info", confidence: "high",
          title: `masscan: ${host.ip}:${p.port}/tcp open`,
          description: `masscan detected an open TCP port (${p.reason}).`,
          ruleId: "masscan/open-port",
          location: { url: `${host.ip}:${p.port}` },
        }));
      }
    }
    await ctx.progress(1, `${n} open ports`);
  },
};

// ────────────────────────── dastardly ────────────────────────────
// PortSwigger Dastardly is distributed primarily as a Docker image; we
// expose an `options.dockerImage` knob so users can point at the local
// image. Dastardly outputs JUnit XML; we parse <testcase> failures.
export const dastardlyScanner: Scanner = {
  id: "web.dastardly",
  name: "Dastardly (Burp DAST)",
  kind: "web",
  description: "PortSwigger's free DAST scanner (Burp engine, ~10 min cap). Runs the official `public.ecr.aws/portswigger/dastardly:latest` Docker image.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("docker", "--version");
    return {
      id: "web.dastardly", name: "Dastardly (Burp DAST)", kind: "web", backend: "cli",
      cliCommand: "docker", cliVersionArg: "--version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "Install Docker. Image: `docker pull public.ecr.aws/portswigger/dastardly:latest`",
      upstream: "https://www.portswigger.net/burp/dastardly",
      license: "Proprietary (free tier)",
      description: "Burp Suite scan engine in a 10-minute CI-friendly mode.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("docker", "--version");
    if (!v) { await ctx.log("warn", "docker not found"); return; }
    const tmp = path.join(os.tmpdir(), `dastardly-${randomUUID()}`);
    await fs.mkdir(tmp, { recursive: true });
    const reportFile = "report.xml";
    const image = (ctx.options.dockerImage as string) || "public.ecr.aws/portswigger/dastardly:latest";
    const args = [
      "run", "--rm",
      "-v", `${tmp}:/dastardly`,
      "-e", `BURP_START_URL=${url.toString()}`,
      "-e", `BURP_REPORT_FILE_PATH=/dastardly/${reportFile}`,
      image,
    ];
    await ctx.log("info", `dastardly via docker (${image})`);
    const r = await runCli("docker", args, { signal: ctx.signal, timeoutMs: 20 * 60 * 1000 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }

    let xml: string;
    try { xml = await fs.readFile(path.join(tmp, reportFile), "utf8"); }
    catch { await ctx.log("warn", "no Dastardly report produced"); return; }
    finally { fs.rm(tmp, { recursive: true, force: true }).catch(() => {}); }

    // Parse JUnit testcases with failure children.
    const tcRe = /<testcase[^>]*name=\"([^\"]+)\"[^>]*classname=\"([^\"]+)\"[\s\S]*?<\/testcase>/g;
    const failRe = /<failure[^>]*message=\"([^\"]+)\"[^>]*>([\s\S]*?)<\/failure>/g;
    let n = 0;
    for (const tc of xml.matchAll(tcRe)) {
      const block = tc[0];
      const ruleName = tc[1];
      const target = tc[2];
      for (const f of block.matchAll(failRe)) {
        n += 1;
        const sev = /critical/i.test(f[1]) ? "critical" : /high/i.test(f[1]) ? "high" : /medium/i.test(f[1]) ? "medium" : "low";
        await ctx.emit(draft({
          severity: sev,
          confidence: "high",
          title: `Dastardly: ${ruleName}`,
          description: f[1],
          ruleId: `dastardly/${ruleName.replace(/\s+/g, "-").toLowerCase()}`,
          location: { url: target },
          evidence: { detail: truncate(f[2].replace(/<!\[CDATA\[|\]\]>/g, ""), 1000) },
        }));
      }
    }
    await ctx.progress(1, `${n} dastardly findings`);
  },
};

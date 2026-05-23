/**
 * nmap adapter — wraps the nmap CLI.
 *
 * Default invocation: `nmap -Pn -sV --top-ports 1000 -oX -` and we parse XML.
 * For SYN scans you'd need root; we stick with default TCP-connect to keep
 * permissions sane.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli } from "../common";
import { safeUrl } from "../common";

interface NmapPort { port: number; state: string; service?: string; product?: string; version?: string; scriptOutputs?: { id: string; output: string }[] }

function parseNmapXml(xml: string): { host?: string; ports: NmapPort[] } {
  const ports: NmapPort[] = [];
  const portRe = /<port[^>]*portid=\"(\d+)\"[\s\S]*?<\/port>/g;
  for (const m of xml.matchAll(portRe)) {
    const block = m[0];
    const port = Number(m[1]);
    const state = (/<state[^>]*state=\"([^\"]+)\"/.exec(block) || [])[1] ?? "unknown";
    if (state !== "open") continue;
    const svc = /<service[^>]*name=\"([^\"]+)\"(?:[^>]*product=\"([^\"]+)\")?(?:[^>]*version=\"([^\"]+)\")?/.exec(block);
    ports.push({
      port,
      state,
      service: svc?.[1],
      product: svc?.[2],
      version: svc?.[3],
    });
  }
  return { ports };
}

export const nmapScanner: Scanner = {
  id: "web.nmap",
  name: "nmap",
  kind: "web",
  description: "Standard nmap top-1000 TCP-connect scan with service/version detection. Falls back gracefully if nmap is not installed.",
  defaultEnabled: false,

  async tool() {
    const v = await detectCli("nmap", "--version");
    return {
      id: "web.nmap",
      name: "nmap",
      kind: "web",
      backend: "cli",
      cliCommand: "nmap",
      cliVersionArg: "--version",
      status: v ? "available" : "missing",
      detectedVersion: v ?? undefined,
      installHint: "`brew install nmap` / `apt install nmap` / https://nmap.org/download.html",
      upstream: "https://nmap.org",
      license: "NPSL (open-source-with-restrictions)",
      description: "Industry-standard network port + service scanner.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const v = await detectCli("nmap", "--version");
    if (!v) { await ctx.log("warn", "nmap not found — skipping"); return; }

    const args = ["-Pn", "-sV", "--top-ports", String(ctx.options.topPorts ?? 1000), "-oX", "-", "-T4", url.hostname];
    await ctx.log("info", `nmap ${v}, scanning ${url.hostname}`);

    const r = await runCli("nmap", args, { signal: ctx.signal, timeoutMs: 30 * 60 * 1000, maxBufferBytes: 32 * 1024 * 1024 });
    if (r.spawnError) { await ctx.log("error", r.spawnError); return; }
    if (!r.stdout.includes("<nmaprun")) { await ctx.log("warn", "no XML output from nmap"); return; }

    const { ports } = parseNmapXml(r.stdout);
    for (const p of ports) {
      const risky = ["mysql","postgresql","postgres","mongodb","redis","memcached","elasticsearch","rdp","vnc","smb","netbios-ssn","docker"].includes((p.service ?? "").toLowerCase());
      await ctx.emit(draft({
        severity: risky ? "high" : "info",
        confidence: "high",
        title: `nmap: ${p.port}/tcp open${p.service ? ` (${p.service}${p.product ? " " + p.product : ""}${p.version ? " " + p.version : ""})` : ""}`,
        description: `nmap detected port ${p.port} open with service "${p.service ?? "unknown"}".${risky ? " This service should rarely be exposed to the internet." : ""}`,
        ruleId: `nmap/${p.service ?? "tcp"}`,
        cwe: ["CWE-200"],
        owasp: ["A05:2021"],
        location: { url: `${url.hostname}:${p.port}` },
        evidence: { product: p.product, version: p.version, service: p.service },
      }));
    }
    await ctx.progress(1, `${ports.length} open ports`);
  },
};

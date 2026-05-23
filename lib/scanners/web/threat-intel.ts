/**
 * Threat-intel passive lookups:
 *
 *   - web.virustotal: lookup the seed domain in VirusTotal; flag if any
 *     vendor classifies it as malicious / suspicious. Requires VT_API_KEY.
 *   - web.shodan:    lookup IP(s) of the seed in Shodan; flag exposed
 *     services that aren't already in our port-scan results. Requires
 *     SHODAN_API_KEY.
 *
 * Passive only — neither calls the target. Both surface real-world signals
 * the target's owner usually doesn't see.
 */

import { promises as dns } from "node:dns";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";

// ───────────────────────── VirusTotal ─────────────────────────────
interface VtResponse {
  data?: {
    attributes?: {
      last_analysis_stats?: { harmless: number; malicious: number; suspicious: number; undetected: number };
      reputation?: number;
      categories?: Record<string, string>;
      last_analysis_results?: Record<string, { category: string; result?: string; engine_name: string }>;
    };
  };
  error?: { code: string; message: string };
}

export const virusTotalScanner: Scanner = {
  id: "web.virustotal",
  name: "VirusTotal Domain Lookup",
  kind: "web",
  description: "Queries VirusTotal for the seed domain's reputation. Flags if any vendor marks it malicious / suspicious. Requires VT_API_KEY env.",
  defaultEnabled: false,
  async tool() {
    return {
      id: "web.virustotal", name: "VirusTotal", kind: "web", backend: "api",
      status: process.env.VT_API_KEY ? "available" : "missing",
      installHint: "Set VT_API_KEY env (free tier: 4 lookups/min).",
      upstream: "https://www.virustotal.com",
      license: "Proprietary (free API tier)",
      description: "VirusTotal domain reputation lookup.",
    };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const apiKey = process.env.VT_API_KEY;
    if (!apiKey) { await ctx.log("info", "VT_API_KEY not set — skipped"); return; }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(seed.hostname) || seed.hostname === "localhost") {
      await ctx.progress(1, "skip — IP / localhost"); return;
    }
    let r;
    try {
      r = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(seed.hostname)}`, {
        headers: { "x-apikey": apiKey },
        signal: ctx.signal,
      });
    } catch { return; }
    if (!r.ok) { await ctx.log("warn", `VT ${r.status}`); return; }
    const j: VtResponse = await r.json();
    const stats = j.data?.attributes?.last_analysis_stats;
    if (!stats) return;
    const flagging = (j.data?.attributes?.last_analysis_results
      ? Object.entries(j.data.attributes.last_analysis_results).filter(([, v]) => v.category === "malicious" || v.category === "suspicious")
      : []).slice(0, 10);
    if (stats.malicious + stats.suspicious > 0) {
      await ctx.emit(draft({
        severity: stats.malicious > 0 ? "high" : "medium", confidence: "high",
        title: `VirusTotal flags ${seed.hostname}: ${stats.malicious} malicious, ${stats.suspicious} suspicious`,
        description: `${flagging.length} vendor(s) classify this domain as malicious or suspicious. Review the engine list — false positives happen, but multiple flags are a red flag.`,
        ruleId: "intel/virustotal",
        cwe: ["CWE-200"],
        location: { url: `https://www.virustotal.com/gui/domain/${seed.hostname}` },
        evidence: { stats, vendors: flagging.map(([engine, v]) => ({ engine, category: v.category, result: v.result })) },
        references: [`https://www.virustotal.com/gui/domain/${seed.hostname}`],
      }));
    } else {
      // Info-level: confirm clean reputation but record categories.
      const categories = j.data?.attributes?.categories ?? {};
      if (Object.keys(categories).length) {
        await ctx.emit(draft({
          severity: "info", confidence: "high",
          title: `VirusTotal categories for ${seed.hostname}: ${Object.values(categories).join(", ")}`,
          description: "VT engines categorized the domain (no flagging). Useful inventory data.",
          ruleId: "intel/virustotal-categories",
          location: { url: `https://www.virustotal.com/gui/domain/${seed.hostname}` },
          evidence: { categories },
        }));
      }
    }
    await ctx.progress(1, "VT done");
  },
};

// ───────────────────────── Shodan ─────────────────────────────
interface ShodanResponse {
  ip_str?: string;
  ports?: number[];
  vulns?: string[];
  data?: Array<{ port: number; product?: string; version?: string; transport?: string }>;
  hostnames?: string[];
  os?: string;
}

export const shodanScanner: Scanner = {
  id: "web.shodan",
  name: "Shodan IP Lookup",
  kind: "web",
  description: "Resolves the seed hostname, queries Shodan for known exposed services / CVEs on that IP. Requires SHODAN_API_KEY env. Passive — only Shodan sees the request.",
  defaultEnabled: false,
  async tool() {
    return {
      id: "web.shodan", name: "Shodan", kind: "web", backend: "api",
      status: process.env.SHODAN_API_KEY ? "available" : "missing",
      installHint: "Set SHODAN_API_KEY env. Membership required for IP queries.",
      upstream: "https://www.shodan.io",
      license: "Proprietary (paid)",
      description: "Internet-wide port scan database.",
    };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const apiKey = process.env.SHODAN_API_KEY;
    if (!apiKey) { await ctx.log("info", "SHODAN_API_KEY not set — skipped"); return; }
    if (seed.hostname === "localhost") return;

    let ips: string[];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(seed.hostname)) ips = [seed.hostname];
    else { try { ips = await dns.resolve4(seed.hostname); } catch { return; } }

    for (const ip of ips.slice(0, 3)) {
      let r;
      try { r = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`, { signal: ctx.signal }); }
      catch { continue; }
      if (!r.ok) continue;
      const j: ShodanResponse = await r.json();
      if (j.vulns?.length) {
        await ctx.emit(draft({
          severity: "critical", confidence: "high",
          title: `Shodan reports ${j.vulns.length} CVE(s) on ${ip}`,
          description: `Internet-wide scan database believes this IP runs services with known CVEs: ${j.vulns.slice(0, 10).join(", ")}.`,
          ruleId: "intel/shodan-cves",
          cve: j.vulns.filter((v) => /^CVE-/i.test(v)),
          location: { url: `https://www.shodan.io/host/${ip}` },
          evidence: { ip, ports: j.ports, vulns: j.vulns },
        }));
      }
      // Surface unexpected open ports vs our own port scan results.
      for (const d of j.data ?? []) {
        if ([80, 443].includes(d.port)) continue;
        await ctx.emit(draft({
          severity: "info", confidence: "high",
          title: `Shodan: ${ip}:${d.port} — ${d.product ?? "unknown"} ${d.version ?? ""}`.trim(),
          description: `Shodan observed this port open at some point. Compare with our active port scan; absent here = closed AT scan time, present here = was open recently.`,
          ruleId: `intel/shodan-port`,
          location: { url: `${ip}:${d.port}` },
          evidence: { product: d.product, version: d.version, transport: d.transport },
        }));
      }
    }
    await ctx.progress(1, `${ips.length} IP(s) queried`);
  },
};

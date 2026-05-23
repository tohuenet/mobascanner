/**
 * Subdomain enumeration — built-in.
 *
 * Two passive sources, no rate-burn on the target:
 *   1. crt.sh — public CT-log search (returns JSON when `?output=json`).
 *      Free, no auth, fairly comprehensive for any host with public TLS.
 *   2. DNS dictionary — small, curated wordlist (50ish prefixes) resolved
 *      via Node's resolveAny against the apex.
 *
 * For each discovered subdomain we issue one HEAD probe to flag whether
 * it's currently web-reachable. Findings are mostly "info" — exposure of
 * unintended subdomains often surfaces dev / staging / admin envs.
 */

import dns from "node:dns/promises";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";

const DNS_DICT = [
  "www", "dev", "staging", "stage", "test", "qa", "uat", "demo",
  "admin", "panel", "dashboard", "portal", "internal", "intranet",
  "api", "api-dev", "api-staging", "api-internal", "graphql", "ws",
  "cdn", "static", "assets", "images", "img", "media", "files", "downloads",
  "mail", "smtp", "imap", "pop", "webmail", "exchange", "owa",
  "git", "gitlab", "gitea", "jenkins", "ci", "cd", "build",
  "vpn", "ssh", "remote", "rdp", "ftp",
  "blog", "support", "help", "kb", "status",
  "shop", "store", "checkout", "pay", "billing",
  "auth", "sso", "login", "id", "accounts", "oauth",
  "monitoring", "metrics", "grafana", "prometheus", "kibana", "elastic",
  "old", "backup", "legacy", "v1", "v2", "beta", "alpha",
];

interface CrtEntry { name_value?: string }

async function fetchCrtSh(apex: string, signal?: AbortSignal): Promise<string[]> {
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`, {
      headers: { "User-Agent": "moba-scanner/0.1 (+crt.sh)" },
      signal,
    });
    if (!r.ok) return [];
    const arr = (await r.json()) as CrtEntry[];
    const set = new Set<string>();
    for (const e of arr) {
      for (const n of (e.name_value ?? "").split("\n")) {
        const cleaned = n.trim().toLowerCase();
        if (cleaned.endsWith(apex) && !cleaned.startsWith("*")) set.add(cleaned);
      }
    }
    return [...set];
  } catch { return []; }
}

async function resolveOne(host: string): Promise<boolean> {
  try { await dns.resolve(host); return true; }
  catch { return false; }
}

// Detect wildcard DNS by resolving a random bogus subdomain. If `*.apex`
// resolves, our DNS-dictionary "hits" mean nothing — every word would
// "resolve". In that case we fall back to crt.sh names (real cert SANs)
// only.
async function detectWildcard(apex: string): Promise<boolean> {
  const rnd = Math.random().toString(36).slice(2, 14);
  return resolveOne(`${rnd}.${apex}`);
}

async function probeWeb(host: string, signal?: AbortSignal): Promise<{ status: number; server?: string } | null> {
  for (const proto of ["https", "http"] as const) {
    try {
      const r = await fetch(`${proto}://${host}/`, { method: "HEAD", redirect: "manual", signal });
      // Server errors aren't meaningfully "reachable" — skip.
      if (r.status >= 500 && r.status < 600) return null;
      // Redirect that leaves the host (parking page, vendor portal, SSO sink)
      // doesn't prove the subdomain hosts a real service.
      if (r.status >= 300 && r.status < 400) {
        const loc = r.headers.get("location") ?? "";
        if (loc) {
          try {
            const target = new URL(loc, `${proto}://${host}/`);
            if (target.host !== host) return null;
          } catch { /* relative-ish — treat as same-host */ }
        }
      }
      return { status: r.status, server: r.headers.get("server") ?? undefined };
    } catch { /* keep trying */ }
  }
  return null;
}

function apexOf(host: string): string {
  // Naive — just keep the last 2 labels. Doesn't handle multi-suffix TLDs (.co.uk),
  // good enough for enum seeds; crt.sh handles its own matching.
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}

export const subdomainEnumScanner: Scanner = {
  id: "web.subdomain-enum",
  name: "Subdomain Enumeration",
  kind: "web",
  description: "Pulls subdomains from crt.sh + a 60-word DNS dictionary. Probes each for web reachability and flags non-production envs.",
  defaultEnabled: false,

  async tool() {
    return {
      id: "web.subdomain-enum",
      name: "Subdomain Enumeration",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Built-in passive subdomain enum (crt.sh + DNS dict).",
      upstream: "https://crt.sh",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;
    const apex = apexOf(url.hostname);
    await ctx.log("info", `apex = ${apex}`);
    await ctx.progress(0.05, "wildcard check");

    // If the apex has wildcard DNS, every DNS-dictionary word "resolves" and
    // we'd flag dozens of phantom subdomains. Fall back to crt.sh names only —
    // those come from real TLS certificate SANs and are authoritative.
    const wildcard = await detectWildcard(apex);
    if (wildcard) {
      await ctx.log("warn", `wildcard DNS detected on *.${apex} — skipping DNS-dictionary (would yield false positives), using crt.sh only`);
    }

    await ctx.progress(0.1, "crt.sh");
    const crt = await fetchCrtSh(apex, ctx.signal);
    await ctx.log("info", `crt.sh returned ${crt.length} candidate names`);

    const dictResolved = wildcard ? [] : (await Promise.all(
      DNS_DICT.map(async (p) => ({ host: `${p}.${apex}`, ok: await resolveOne(`${p}.${apex}`) })),
    )).filter((r) => r.ok).map((r) => r.host);

    // Source tracking: a name from crt.sh is an authoritative cert SAN (high
    // confidence); a name that merely resolved via DNS guess is circumstantial
    // (medium).
    const crtSet = new Set(crt);
    const all = Array.from(new Set([...crt, ...dictResolved])).sort().slice(0, 200);
    await ctx.progress(0.4, `${all.length} unique candidates`);

    let probed = 0;
    const flagged: { host: string; status: number; server?: string; reason: string; severity: "low" | "info" | "medium"; confidence: "high" | "medium" }[] = [];
    const concurrency = 12;
    let i = 0;
    const workers = Array.from({ length: concurrency }, async () => {
      while (i < all.length && !ctx.signal.aborted) {
        const k = i++;
        const host = all[k];
        const r = await probeWeb(host, ctx.signal);
        probed += 1;
        if (probed % 10 === 0) await ctx.progress(0.4 + 0.6 * (probed / all.length), `probed ${probed}/${all.length}`);
        if (!r) continue;
        const lower = host.toLowerCase();
        let severity: "low" | "info" | "medium" = "info";
        let reason = "subdomain reachable";
        if (/\b(dev|staging|stage|qa|uat|test|demo|beta|alpha|internal|intranet|admin|jenkins|gitlab|grafana|kibana|sso)\b/.test(lower)) {
          severity = "medium";
          reason = "non-production / management subdomain reachable from the public internet";
        } else if (/\b(old|backup|legacy|v1|v2)\b/.test(lower)) {
          severity = "low";
          reason = "legacy subdomain reachable — old code paths often miss patches";
        }
        const confidence: "high" | "medium" = crtSet.has(host) ? "high" : "medium";
        flagged.push({ host, status: r.status, server: r.server, reason, severity, confidence });
      }
    });
    await Promise.all(workers);

    for (const f of flagged) {
      await ctx.emit(draft({
        severity: f.severity,
        confidence: f.confidence,
        title: `Subdomain reachable: ${f.host}`,
        description: f.reason,
        ruleId: "subdomain-enum",
        cwe: ["CWE-200"],
        owasp: ["A05:2021"],
        location: { url: `https://${f.host}/` },
        evidence: { status: f.status, server: f.server, source: crtSet.has(f.host) ? "crt.sh" : "dns-dict" },
        references: [`https://crt.sh/?q=%25.${apex}`],
      }));
    }
    await ctx.progress(1, `${flagged.length} subdomains`);
  },
};

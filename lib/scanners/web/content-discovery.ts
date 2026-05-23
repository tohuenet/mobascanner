/**
 * Content discovery — built-in dirbust against a curated wordlist.
 *
 * Wordlist sourced from OWASP / SecLists "common.txt" highlights —
 * trimmed to ~250 paths that have a high signal:noise ratio (admin panels,
 * config files, debug endpoints, common framework dumps). For exhaustive
 * coverage, install ffuf and use the `web.ffuf` adapter instead.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";

// High-signal paths only. Order roughly by criticality.
const PATHS: string[] = [
  // VCS / deploy artifacts
  ".git/HEAD", ".git/config", ".git/index",
  ".svn/entries", ".hg/store/00changelog.i", ".bzr/branch/branch-name",
  ".DS_Store",
  // Env / secrets
  ".env", ".env.local", ".env.production", ".env.development",
  ".envrc", ".aws/credentials", ".npmrc", ".pypirc", "config.json",
  "wp-config.php.bak", "wp-config.php~", "settings.py", "config.yml",
  "secrets.yml", "credentials.yml", "database.yml",
  // Backups
  "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "db.sql",
  "site.zip", "www.zip", "html.zip", "site.tar.gz",
  // Server status / debug
  "server-status", "server-info", "phpinfo.php", "info.php", "test.php",
  "status", "metrics", "actuator", "actuator/health", "actuator/env",
  "actuator/heapdump", "actuator/configprops", "actuator/mappings",
  "_debug", "debug", "debug.php", "trace", "trace.axd",
  // Admin panels
  "admin", "admin/", "administrator/", "wp-admin/", "wp-login.php",
  "user/login", "console", "manager/html", "phpmyadmin/", "pma/",
  "adminer.php", "kibana", "grafana/login",
  // API / docs
  "api", "api/", "api/v1", "api/v2", "api/swagger", "swagger.json",
  "swagger-ui.html", "openapi.json", "openapi.yaml", "docs", "graphql",
  "graphiql", "playground", "explorer", "altair",
  // Framework defaults
  "robots.txt", "sitemap.xml", "humans.txt", "security.txt", ".well-known/security.txt",
  ".well-known/openid-configuration", ".well-known/jwks.json",
  "crossdomain.xml", "clientaccesspolicy.xml",
  // CMS-specific
  "wp-json/wp/v2/users", "wp-json/", "xmlrpc.php",
  "drupal/CHANGELOG.txt", "user/register",
  "joomla/administrator/", "administrator/manifests/files/joomla.xml",
  // Common paths
  "login", "signin", "signup", "register", "forgot-password",
  "uploads/", "files/", "static/", "assets/",
  // Storage / config dump
  "config.php.bak", "settings.json", "appsettings.json", "web.config",
  "conf/server.xml", "WEB-INF/web.xml",
  // Misc
  "console", "shell", "cmd.jsp", "test.jsp", "jenkins", "jenkins/script",
  "git/", "gitlab/", "gitea/",
];

function classifyHit(path: string, body: string): { severity: "critical" | "high" | "medium" | "low" | "info"; reason: string; cwe?: string[] } {
  const lower = path.toLowerCase();
  if (/\.git\/|\.svn\/|\.hg\//.test(lower)) return { severity: "critical", reason: "VCS metadata exposed — full source can usually be reconstructed", cwe: ["CWE-538"] };
  if (/\.env|credentials|secrets|database\.yml|wp-config|settings\.py|appsettings/.test(lower)) return { severity: "critical", reason: "configuration / credential file exposed", cwe: ["CWE-538"] };
  if (/backup|dump|\.sql\b|\.zip$|\.tar\.gz$/.test(lower)) return { severity: "high", reason: "backup or database dump exposed", cwe: ["CWE-538"] };
  if (/actuator\/(env|heapdump|configprops|mappings)/.test(lower)) return { severity: "high", reason: "Spring Boot Actuator endpoint discloses runtime config", cwe: ["CWE-200"] };
  if (/phpinfo|info\.php|server-info|server-status/.test(lower)) return { severity: "high", reason: "server diagnostic page exposed", cwe: ["CWE-200"] };
  if (/swagger|openapi|graphiql|playground/.test(lower)) return { severity: "medium", reason: "API spec / explorer exposed — broadens reconnaissance surface", cwe: ["CWE-200"] };
  if (/admin|manager|adminer|phpmyadmin|wp-admin|wp-login|console/.test(lower)) return { severity: "medium", reason: "admin / management interface reachable", cwe: ["CWE-284"] };
  if (/xmlrpc\.php/.test(lower) && body) return { severity: "medium", reason: "WordPress XML-RPC endpoint enabled (auth brute-force, SSRF risk)", cwe: ["CWE-307"] };
  if (/\.ds_store/.test(lower)) return { severity: "low", reason: "macOS .DS_Store leaks directory listing", cwe: ["CWE-200"] };
  return { severity: "info", reason: "discovered" };
}

interface ProbeResult {
  status: number;
  finalHost: string;
  finalUrl: string;
  len: number;
  contentType: string | null;
  sig: string;
  body: string;
}

// Allocation-light 32-bit FNV-1a hash → hex. Just needs to collide for
// byte-identical normalized bodies; not cryptographic.
function cheapHash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

// Fingerprint a response body so "same shape" pages collide. Strips the probed
// path (often echoed back in 404 bodies) and digits (nonces, timestamps, counts)
// so two distinct bogus paths produce the same signature.
function fingerprint(body: string, pathToken: string): string {
  const norm = body
    .split(pathToken).join("")
    .replace(/\d+/g, "")
    .replace(/\s+/g, " ")
    .slice(0, 2048);
  return `${norm.length}:${cheapHash(norm)}`;
}

// One GET that follows redirects, so we evaluate where the path actually lands
// — not the intermediate 3xx. Returns null on network error.
async function probePath(
  url: string,
  pathToken: string,
  headers: HeadersInit,
  signal: AbortSignal,
): Promise<ProbeResult | null> {
  try {
    const res = await fetch(url, { method: "GET", headers, redirect: "follow", signal });
    const body = (await res.text().catch(() => "")).slice(0, 4096);
    const clen = Number(res.headers.get("content-length"));
    const len = Number.isFinite(clen) && clen > 0 ? clen : body.length;
    let finalHost = "";
    try { finalHost = new URL(res.url).host; } catch { /* ignore */ }
    return {
      status: res.status,
      finalHost,
      finalUrl: res.url || url,
      len,
      contentType: res.headers.get("content-type"),
      sig: fingerprint(body, pathToken),
      body,
    };
  } catch { return null; }
}

// True when a probe is indistinguishable from the target's "not found" answer:
// same status AND (identical content signature OR length within 5%). This is
// what filters catch-all redirects, SPA 404 shells, and soft-200 error pages.
function matchesBaseline(p: ProbeResult, baselines: ProbeResult[]): boolean {
  return baselines.some((b) =>
    p.status === b.status &&
    (p.sig === b.sig || Math.abs(p.len - b.len) <= Math.max(64, b.len * 0.05)));
}

export const contentDiscoveryScanner: Scanner = {
  id: "web.content-discovery",
  name: "Content Discovery",
  kind: "web",
  description: "Probes ~250 high-signal paths (VCS, .env, backups, admin panels, actuator, swagger, server-status). For exhaustive coverage install ffuf.",
  defaultEnabled: false,

  async tool() {
    return {
      id: "web.content-discovery",
      name: "Content Discovery",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Built-in dirbust with curated high-signal wordlist.",
      upstream: "https://github.com/danielmiessler/SecLists",
    };
  },

  async run(ctx) {
    const start = safeUrl(ctx.target.value);
    if (!start) { await ctx.log("error", "invalid URL"); return; }
    const base = `${start.protocol}//${start.host}`;
    const baseHost = start.host;
    const concurrency = Math.min(Number(ctx.options.concurrency) || 16, 64);
    const headers: HeadersInit = {
      "User-Agent": "moba-scanner/0.1 (+content-discovery)",
      ...(ctx.target.auth?.headers ?? {}),
    };

    // ── Baseline: learn what "this path does not exist" looks like on the
    // target before we probe anything from the wordlist. Catch-all redirects
    // (trailing-slash normalization), SPA 404 shells, and soft-200 error pages
    // all produce a stable response shape that we must NOT treat as a hit.
    // We probe three variants: bare random, trailing-slash random, and the
    // site root — every later probe is compared against these.
    const rnd = () => Math.random().toString(36).slice(2, 12);
    const bogus1 = rnd();
    const bogus2 = `${rnd()}/`;
    const baselineProbes = [bogus1, bogus2, ""];
    const baselines: ProbeResult[] = [];
    for (const probe of baselineProbes) {
      const r = await probePath(`${base}/${probe}`, probe || "/", headers, ctx.signal);
      if (r) baselines.push(r);
    }
    if (baselines.length) {
      const b = baselines[0];
      await ctx.log(
        "info",
        `baseline: bogus path "/${bogus1}" → status ${b.status}, ${b.len}B, sig ${b.sig}, final ${b.finalUrl}`,
      );
    } else {
      await ctx.log("warn", "baseline probe failed — proceeding without catch-all filtering");
    }

    let idx = 0;
    let done = 0;
    let openCount = 0;
    const total = PATHS.length;

    const workers = Array.from({ length: concurrency }, async () => {
      while (idx < PATHS.length && !ctx.signal.aborted) {
        const i = idx++;
        const p = PATHS[i];
        const url = `${base}/${p}`;
        const r = await probePath(url, p, headers, ctx.signal);
        done += 1;
        if (done % 16 === 0) await ctx.progress(done / total, `${done}/${total}, ${openCount} hits`);
        if (!r) continue;

        // Redirected off the target host (open-redirect / parking / vendor SSO
        // sink) — not evidence that the path exists on the target.
        if (r.finalHost && r.finalHost !== baseHost) continue;
        // Hard not-found.
        if (r.status === 404 || r.status === 410) continue;

        // Auth gate: path exists but is protected. Useful but low-signal.
        if (r.status === 401 || r.status === 403) {
          const c = classifyHit(p, "");
          await ctx.emit(draft({
            severity: c.severity === "critical" ? "high" : "low",
            confidence: "low",
            title: `Path exists but auth-gated: /${p} (${r.status})`,
            description: `${c.reason}. Authentication is required.`,
            ruleId: `content-discovery/${p}`,
            location: { url },
            evidence: { status: r.status },
          }));
          continue;
        }

        // Catch-all / soft-404 / SPA shell → indistinguishable from "not found"
        // on this target. This is the change that kills the widata.vn-style
        // 308-trailing-slash false positives.
        if (matchesBaseline(r, baselines)) continue;
        // Cheap secondary guard for generic textual "not found" bodies.
        const looksLikeApp404 = /not\s+found|404/i.test(r.body) && r.body.length < 2000 && !/<svg|<form/i.test(r.body);
        if (looksLikeApp404) continue;
        // After follow, anything ≥400 that survived (and isn't auth) is noise.
        if (r.status >= 400) continue;

        const c = classifyHit(p, r.body);
        openCount += 1;
        const redirected = r.finalUrl && r.finalUrl !== url;
        await ctx.emit(draft({
          severity: c.severity,
          confidence: "medium",
          title: `Path reachable: /${p} (${r.status})`,
          description: c.reason,
          ruleId: `content-discovery/${p}`,
          cwe: c.cwe,
          owasp: ["A05:2021"],
          location: { url },
          evidence: {
            status: r.status,
            contentType: r.contentType,
            bytes: r.len,
            ...(redirected ? { finalUrl: r.finalUrl } : {}),
          },
          remediation: "Restrict the path or remove it from the deployment. If it's intentional, gate it behind authentication.",
        }));
      }
    });
    await Promise.all(workers);
    await ctx.progress(1, `${openCount} paths`);
  },
};

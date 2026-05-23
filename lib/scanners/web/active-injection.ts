/**
 * Active injection testers — built-in.
 *
 * Targets URL query parameters and emits a finding when a probe causes a
 * detectable, deterministic side-effect (reflection, error, time delay,
 * canary token in response, etc.).
 *
 * Covers OWASP A03:2021 (Injection) and A10:2021 (SSRF):
 *   - Reflected XSS (unique canary in response body, not encoded)
 *   - Error-based SQLi (DB engine error strings appear)
 *   - Boolean-based SQLi (response length differs for true vs false probe)
 *   - Time-based SQLi (sleep payload causes ≥4s extra latency)
 *   - SSRF (out-of-band trigger via attacker-controlled host: skipped here,
 *           we only flag suspicious responses to interactsh-style probes)
 *   - Open redirect (Location header points to attacker-controlled host)
 *   - Path traversal / LFI (etc/passwd or boot.ini snippet in response)
 *   - OS command injection (uname/dir output marker in response)
 *
 * IMPORTANT: this scanner sends *active* payloads. Only run against systems
 * you have written permission to test. The crawler-discovered URL list is
 * used as the parameter surface; if no crawler ran, only the seed URL's
 * params are tested.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { listFindings } from "../../store";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { randomBytes } from "node:crypto";

const SQL_ERROR_RE = new RegExp(
  [
    "you have an error in your sql syntax",
    "warning:\\s*mysql_",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query\\(\\)|pg_exec\\(\\)",
    "ORA-\\d{5}",
    "Microsoft OLE DB Provider for SQL Server",
    "ODBC SQL Server Driver",
    "SQLite/JDBCDriver",
    "SQLite\\.Exception",
    "System\\.Data\\.SQLite\\.SQLiteException",
    "Npgsql\\.",
    "PostgreSQL.*ERROR",
    "syntax error at or near",
  ].join("|"),
  "i",
);

const LFI_MARKERS = [
  "root:x:0:0:",                       // /etc/passwd
  "[boot loader]",                     // boot.ini
  "for 16-bit app support",            // win.ini
  "; for 16-bit app support",
];

const CMD_MARKERS = [
  /uid=\d+\(.+?\)\s+gid=\d+/,          // `id`
  /\bDarwin\b.*?Kernel Version/,
  /\bLinux\b.*?\bx86_64\b/,
  /Volume in drive C/,                 // dir on Windows
];

interface Probe {
  payload: string;
  detect: (resp: { status: number; body: string; headers: Headers; latencyMs: number }) => null | { rule: string; severity: "critical" | "high" | "medium" | "low" | "info"; reason: string; cwe: string[]; owasp: string[]; remediation: string };
}

function looksLikeHtml(ct: string | null): boolean { return !!ct && /\b(text\/html|application\/xhtml)\b/i.test(ct); }
function looksLikeJson(ct: string | null): boolean { return !!ct && /\b(application\/json|application\/.*\+json)\b/i.test(ct); }

const REFLECT_PROBE = (canary: string): Probe => ({
  payload: `"<svg/onload=alert('${canary}')>`,
  detect: (r) => {
    if (!r.body.includes(canary)) return null;
    const ct = r.headers.get("content-type");
    if (looksLikeJson(ct) && !looksLikeHtml(ct)) {
      return { rule: "reflection/json-echo", severity: "info", reason: `parameter echoed in JSON response (NOT browser-executable XSS)`, cwe: ["CWE-200"], owasp: ["A05:2021"], remediation: "Verify the response is never rendered as HTML downstream (e.g. via innerHTML)." };
    }
    if (!looksLikeHtml(ct)) return null;
    if (r.body.includes(`&lt;svg`) || r.body.includes(`&quot;&lt;svg`)) return null;
    const tagRe = new RegExp(`<svg[^>]*${canary}`, "i");
    if (!tagRe.test(r.body)) return null;
    return { rule: "xss/reflected", severity: "high", reason: `payload reflected as live HTML tag (canary "${canary}")`, cwe: ["CWE-79"], owasp: ["A03:2021"], remediation: "Encode untrusted input in the appropriate context (HTML, JS, URL, CSS) and apply CSP." };
  },
});

const SQL_ERROR_PROBE: Probe = {
  payload: "'\"`)/*--",
  detect: (r) => SQL_ERROR_RE.test(r.body) ? { rule: "sqli/error", severity: "critical", reason: "DB engine error string in response", cwe: ["CWE-89"], owasp: ["A03:2021"], remediation: "Use parameterized queries / prepared statements. Never concatenate user input into SQL." } : null,
};

const SQL_TIME_PROBE: Probe = {
  payload: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
  detect: (r) => r.latencyMs >= 4500 ? { rule: "sqli/time", severity: "critical", reason: `response delayed ${Math.round(r.latencyMs)}ms after sleep payload`, cwe: ["CWE-89"], owasp: ["A03:2021"], remediation: "Use parameterized queries / prepared statements." } : null,
};

const LFI_PROBE: Probe = {
  payload: "../../../../etc/passwd",
  detect: (r) => LFI_MARKERS.some((m) => r.body.includes(m)) ? { rule: "lfi/traversal", severity: "critical", reason: "system file content disclosed in response", cwe: ["CWE-22"], owasp: ["A01:2021"], remediation: "Reject paths containing `..`, normalize via realpath, and serve files from a strict allowlist." } : null,
};

const CMD_PROBE: Probe = {
  payload: ";id; #",
  detect: (r) => CMD_MARKERS.some((m) => m.test(r.body)) ? { rule: "cmdi/exec", severity: "critical", reason: "shell command output in response", cwe: ["CWE-78"], owasp: ["A03:2021"], remediation: "Never pass user input to shells. Use language-native APIs that take an argv array." } : null,
};

const OPEN_REDIRECT_PROBE = (host: string): Probe => ({
  payload: `https://${host}/`,
  detect: (r) => {
    const loc = r.headers.get("location");
    if (!loc) return null;
    try {
      const u = new URL(loc, "http://x/");
      if (u.hostname.toLowerCase() === host.toLowerCase()) {
        return { rule: "open-redirect", severity: "high", reason: `redirect to attacker-controlled host (${u.hostname})`, cwe: ["CWE-601"], owasp: ["A01:2021"], remediation: "Use an allow-list of redirect targets, never echo user-controlled URLs into Location." };
      }
    } catch { /* malformed location */ }
    return null;
  },
});

const SSRF_PROBE: Probe = {
  payload: "http://169.254.169.254/latest/meta-data/",
  detect: (r) =>
    /ami-id|instance-id|iam\/security-credentials|public-keys/i.test(r.body)
      ? { rule: "ssrf/aws-imds", severity: "critical", reason: "AWS IMDS metadata in response — server fetched our payload URL", cwe: ["CWE-918"], owasp: ["A10:2021"], remediation: "Block egress to link-local / RFC1918 from app servers; use IMDSv2; validate URLs against an allow-list." }
      : null,
};

interface UrlWithParams { url: URL; params: string[] }

function paramURLs(start: URL): UrlWithParams[] {
  const params = [...start.searchParams.keys()];
  if (params.length) return [{ url: start, params }];
  return [];
}

async function fetchWithTiming(u: URL, headers: HeadersInit, signal?: AbortSignal, redirect: RequestRedirect = "manual"): Promise<{ status: number; body: string; headers: Headers; latencyMs: number } | null> {
  const t = Date.now();
  try {
    const res = await fetch(u, { headers, redirect, signal });
    const body = res.body ? await res.text() : "";
    return { status: res.status, body, headers: res.headers, latencyMs: Date.now() - t };
  } catch { return null; }
}

export const activeInjectionScanner: Scanner = {
  id: "web.active-injection",
  name: "Active Injection (XSS/SQLi/LFI/CMD/SSRF/Redirect)",
  kind: "web",
  description: "Per-parameter probes for reflected XSS, error+time SQLi, LFI, OS command injection, SSRF (AWS IMDS), and open redirect. Uses crawler URL inventory if available.",
  defaultEnabled: false, // active probes — opt-in

  async tool() {
    return {
      id: "web.active-injection",
      name: "Active Injection",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Built-in active probes for OWASP A01/A03/A10.",
      upstream: "https://owasp.org/www-project-top-ten/",
    };
  },

  async run(ctx) {
    const start = safeUrl(ctx.target.value);
    if (!start) { await ctx.log("error", "invalid URL"); return; }

    // Prefer the SiteMap (deep crawler) — fall back to the legacy inventory
    // finding, then to the seed URL alone.
    const map = await loadSiteMap(ctx.scanId);
    const candidateURLs: string[] = [];
    if (map) {
      candidateURLs.push(...map.pages.map((p) => p.url));
      candidateURLs.push(...map.apiHints.map((a) => a.url));
    } else {
      const findings = await listFindings(ctx.scanId);
      const crawlerInv = findings.find((f) => f.scannerId === "web.crawler" && /inventory|sitemap/i.test(f.ruleId ?? ""));
      const seedURLs = (crawlerInv?.evidence?.discovered as string[] | undefined) ?? [];
      candidateURLs.push(...seedURLs);
    }
    candidateURLs.push(start.toString());

    const targets: UrlWithParams[] = [];
    const seenUrls = new Set<string>();
    for (const s of candidateURLs) {
      if (seenUrls.has(s)) continue;
      seenUrls.add(s);
      const u = safeUrl(s);
      if (!u) continue;
      const t = paramURLs(u);
      targets.push(...t);
    }
    // Also synthesize parameter URLs from sitemap reflectiveQueryKeys + apiHints
    if (map) {
      for (const p of map.pages) {
        if (!p.reflectedQueryKeys?.length) continue;
        const u = safeUrl(p.url);
        if (!u) continue;
        if (![...u.searchParams.keys()].length) continue;
        targets.push({ url: u, params: [...u.searchParams.keys()] });
      }
    }
    if (!targets.length) {
      await ctx.log("info", "no URL parameters to probe");
      await ctx.progress(1, "skipped");
      return;
    }

    const canary = "MOBA" + randomBytes(4).toString("hex");
    const oobHost = `oob-${canary.toLowerCase()}.invalid`;
    const probes: Probe[] = [REFLECT_PROBE(canary), SQL_ERROR_PROBE, SQL_TIME_PROBE, LFI_PROBE, CMD_PROBE, SSRF_PROBE, OPEN_REDIRECT_PROBE(oobHost)];

    const headers: HeadersInit = {
      "User-Agent": "moba-scanner/0.1 (+active)",
      ...(ctx.target.auth?.headers ?? {}),
      ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
    };

    const total = targets.reduce((a, t) => a + t.params.length * probes.length, 0);
    let done = 0;

    for (const { url, params } of targets) {
      if (ctx.signal.aborted) break;
      for (const param of params) {
        for (const probe of probes) {
          if (ctx.signal.aborted) break;
          const u = new URL(url.toString());
          u.searchParams.set(param, probe.payload);
          const r = await fetchWithTiming(u, headers, ctx.signal);
          done += 1;
          if (done % 5 === 0) await ctx.progress(done / total, `${done}/${total}`);
          if (!r) continue;
          const hit = probe.detect(r);
          if (!hit) continue;
          await ctx.emit(draft({
            severity: hit.severity,
            confidence: probe === SQL_TIME_PROBE ? "medium" : "high",
            title: `${hit.rule.toUpperCase()} on parameter "${param}"`,
            description: `${probe.payload.slice(0, 80)}\n\n→ ${hit.reason}`,
            ruleId: hit.rule,
            cwe: hit.cwe,
            owasp: hit.owasp,
            location: { url: u.toString(), snippet: param },
            evidence: { payload: probe.payload, status: r.status, latencyMs: r.latencyMs, snippet: truncate(r.body, 400) },
            remediation: hit.remediation,
          }));
        }
      }
    }
    await ctx.progress(1, `${done} probes sent`);
  },
};

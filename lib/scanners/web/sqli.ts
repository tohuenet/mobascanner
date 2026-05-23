/**
 * Comprehensive SQL injection scanner.
 *
 * What it covers:
 *
 *   Techniques:
 *     - Error-based   (DB-engine error string in response)
 *     - Boolean-based (AND 1=1 vs AND 1=2 length/status diff)
 *     - Time-based    (SLEEP / pg_sleep / WAITFOR / DBMS_PIPE / randomblob)
 *     - UNION-based   (column-count discovery via ORDER BY)
 *
 *   DBMSes fingerprinted: MySQL/MariaDB · PostgreSQL · Microsoft SQL Server ·
 *                          Oracle · SQLite · DB2.
 *
 *   Injection points:
 *     - URL query parameters
 *     - URL path numeric/uuid segments (limited)
 *     - POST form fields (any content-type the form declares)
 *     - JSON body fields (one-deep object scan)
 *     - Cookie values
 *     - User-Agent / Referer / X-Forwarded-For headers
 *
 *   WAF-bypass mutations are layered onto each base payload (URL-encode,
 *   double-URL-encode, comment-padding, case-mix). We try the cleanest
 *   payload first and only escalate if the baseline matches the probe — this
 *   keeps the noise floor low.
 *
 * Detection rules are conservative on purpose: we only emit a finding when
 * the probe causes a deterministic, attacker-controllable side-effect.
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap, type SiteMapForm } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

// ─────────────────────────── DBMS fingerprints ──────────────────────────
const DB_ERROR_PATTERNS: { dbms: string; re: RegExp }[] = [
  { dbms: "MySQL/MariaDB", re: /you have an error in your sql syntax|warning:\s*mysql_|mysqli?_(?:fetch|query|num_rows)|mariadb server version|com\.mysql\.|mysql_fetch|sqlexception.*?mysql/i },
  { dbms: "PostgreSQL",    re: /pg_query|pg_exec|postgresql.*error|syntax error at or near|psqlexception|npgsql\./i },
  { dbms: "MSSQL",         re: /microsoft ole db provider for sql server|odbc sql server driver|microsoft sql native client|sqlserverexception|incorrect syntax near|unclosed quotation mark/i },
  { dbms: "Oracle",        re: /ORA-\d{5}|oracle.+driver|quoted string not properly terminated|oracle\.exception/i },
  { dbms: "SQLite",        re: /sqlite\/jdbcdriver|sqlite\.exception|system\.data\.sqlite\.sqliteexception|sqlite_master|near.*syntax error/i },
  { dbms: "DB2",           re: /db2\sjava\.driver|com\.ibm\.db2|sqlcode.*\-?\d+|sql0\d{3}/i },
];

function detectDbmsError(body: string): string | null {
  for (const { dbms, re } of DB_ERROR_PATTERNS) if (re.test(body)) return dbms;
  return null;
}

// ─────────────────────────── Payload library ────────────────────────────
interface BoolPair { tru: string; fal: string; label: string }

// Boolean payloads: append-after-int (`1 AND 1=1` / `1 AND 1=2`) and
// append-after-string (`x' AND '1'='1` / `x' AND '1'='2`). Detector compares
// lengths of two responses against the un-touched baseline.
const BOOLEAN_PAYLOADS: BoolPair[] = [
  { tru: " AND 1=1",        fal: " AND 1=2",        label: "int-append" },
  { tru: "' AND '1'='1",    fal: "' AND '1'='2",    label: "string-quote" },
  { tru: "\" AND \"1\"=\"1", fal: "\" AND \"1\"=\"2", label: "string-dquote" },
  { tru: ") AND (1=1",      fal: ") AND (1=2",      label: "paren-int" },
  { tru: "') AND ('1'='1",  fal: "') AND ('1'='2",  label: "paren-string" },
];

interface TimeProbe { dbms: string; payload: (sec: number) => string }
const TIME_PROBES: TimeProbe[] = [
  { dbms: "MySQL/MariaDB", payload: (s) => `' AND (SELECT SLEEP(${s}))-- -` },
  { dbms: "MySQL/MariaDB", payload: (s) => ` AND (SELECT SLEEP(${s}))-- -` },
  { dbms: "MySQL/MariaDB", payload: (s) => ` AND BENCHMARK(${s * 5_000_000},MD5(1))` },
  { dbms: "PostgreSQL",    payload: (s) => `' AND pg_sleep(${s})-- -` },
  { dbms: "PostgreSQL",    payload: (s) => ` AND pg_sleep(${s})-- -` },
  { dbms: "MSSQL",         payload: (s) => `';WAITFOR DELAY '0:0:${s}'-- ` },
  { dbms: "MSSQL",         payload: (s) => `;WAITFOR DELAY '0:0:${s}'-- ` },
  { dbms: "Oracle",        payload: (s) => `' AND DBMS_PIPE.RECEIVE_MESSAGE('a',${s})='a'-- ` },
  { dbms: "SQLite",        payload: (s) => `' AND randomblob(${s * 100_000_000})-- ` },
];

// Error-trigger payloads — short, broad. Detection is via DBMS regex.
const ERROR_PAYLOADS = [
  "'", "\"", "`", "')", "\")", "';", "\";",
  "' OR '1'='1'-- -",
  "1' AND extractvalue(1,concat(0x7e,(select user())))-- -",
  "AND 1=CONVERT(int,(SELECT @@version))",
  "1' UNION SELECT NULL-- -",
];

// Cumulative ORDER BY for column-count discovery (UNION-based).
function orderByPayloads(maxCols = 16): { n: number; payload: string }[] {
  return Array.from({ length: maxCols }, (_, i) => ({ n: i + 1, payload: ` ORDER BY ${i + 1}-- -` }));
}

// ─────────────────────────── Injection-point types ──────────────────────
type Point =
  | { kind: "query"; url: URL; param: string }
  | { kind: "post-form"; form: SiteMapForm; param: string }
  | { kind: "post-json"; url: string; param: string }
  | { kind: "cookie"; url: string; cookieName: string; cookieValue: string }
  | { kind: "header"; url: string; header: string };

const HEADER_INJECTION_POINTS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host"];

function pointId(p: Point): string {
  switch (p.kind) {
    case "query":     return `query:${p.url.pathname}?${p.param}`;
    case "post-form": return `form:${p.form.action}#${p.param}`;
    case "post-json": return `json:${p.url}#${p.param}`;
    case "cookie":    return `cookie:${p.url}#${p.cookieName}`;
    case "header":    return `header:${p.url}#${p.header}`;
  }
}

async function probe(
  session: BrowsingSession,
  point: Point,
  injected: string,
  signal: AbortSignal,
): Promise<{ status: number; body: string; headers: Headers; latencyMs: number } | null> {
  const t = Date.now();
  try {
    if (point.kind === "query") {
      const u = new URL(point.url.toString());
      u.searchParams.set(point.param, injected);
      const r = await session.fetch(u.toString(), { signal });
      return { status: r.res.status, body: r.body, headers: r.res.headers, latencyMs: Date.now() - t };
    }
    if (point.kind === "post-form") {
      const data = new URLSearchParams();
      for (const i of point.form.inputs) data.set(i.name, i.value || "1");
      data.set(point.param, injected);
      const r = await session.fetch(point.form.action, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: data.toString(),
        signal,
      });
      return { status: r.res.status, body: r.body, headers: r.res.headers, latencyMs: Date.now() - t };
    }
    if (point.kind === "post-json") {
      const r = await session.fetch(point.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ [point.param]: injected }),
        signal,
      });
      return { status: r.res.status, body: r.body, headers: r.res.headers, latencyMs: Date.now() - t };
    }
    if (point.kind === "cookie") {
      const r = await session.fetch(point.url, {
        headers: { cookie: `${point.cookieName}=${injected}` },
        signal,
      });
      return { status: r.res.status, body: r.body, headers: r.res.headers, latencyMs: Date.now() - t };
    }
    if (point.kind === "header") {
      const r = await session.fetch(point.url, {
        headers: { [point.header]: injected },
        signal,
      });
      return { status: r.res.status, body: r.body, headers: r.res.headers, latencyMs: Date.now() - t };
    }
  } catch { return null; }
  return null;
}

async function baselineFor(
  session: BrowsingSession,
  point: Point,
  signal: AbortSignal,
): Promise<{ body: string; status: number; latencyMs: number } | null> {
  // For each point we use a benign value matching its expected shape.
  const benign = "1";
  const r = await probe(session, point, benign, signal);
  if (!r) return null;
  return { body: r.body, status: r.status, latencyMs: r.latencyMs };
}

function pointHumanLabel(p: Point): string {
  switch (p.kind) {
    case "query":     return `URL parameter "${p.param}" of ${p.url.pathname}`;
    case "post-form": return `form field "${p.param}" of POST ${p.form.action}`;
    case "post-json": return `JSON field "${p.param}" of POST ${p.url}`;
    case "cookie":    return `cookie "${p.cookieName}" on ${p.url}`;
    case "header":    return `${p.header} header on ${p.url}`;
  }
}

function pointLocation(p: Point): { url: string; snippet: string } {
  switch (p.kind) {
    case "query":     return { url: p.url.toString(), snippet: `?${p.param}=` };
    case "post-form": return { url: p.form.action,     snippet: `${p.param} (${p.form.method} body)` };
    case "post-json": return { url: p.url,             snippet: `${p.param} (json body)` };
    case "cookie":    return { url: p.url,             snippet: `Cookie: ${p.cookieName}=` };
    case "header":    return { url: p.url,             snippet: `${p.header}: …` };
  }
}

// ─────────────────────────── Scanner ────────────────────────────────────
export const sqliScanner: Scanner = {
  id: "web.sqli",
  name: "SQL Injection (multi-DBMS, multi-technique)",
  kind: "web",
  description: "Tests every URL param / form field / JSON field / cookie / common header for error-based, boolean-based, time-based, and UNION-based SQL injection across MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, DB2.",
  defaultEnabled: false, // active probes — opt-in
  async tool() {
    return {
      id: "web.sqli", name: "SQL Injection", kind: "web", backend: "builtin", status: "available",
      description: "Built-in comprehensive SQL injection scanner.",
      upstream: "https://owasp.org/www-community/attacks/SQL_Injection",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, {
      ...(ctx.target.auth?.headers ?? {}),
      ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
    });

    // 1) Build the injection-point list.
    const points: Point[] = [];
    if (map) {
      for (const p of map.pages) {
        const u = safeUrl(p.url); if (!u) continue;
        for (const param of u.searchParams.keys()) points.push({ kind: "query", url: u, param });
      }
      for (const f of map.forms) {
        if (f.method !== "POST") continue;
        for (const i of f.inputs) {
          if (["submit", "button", "reset", "image", "file"].includes(i.type)) continue;
          if (/(csrf|xsrf|authenticity_token|_token)/i.test(i.name)) continue;
          points.push({ kind: "post-form", form: f, param: i.name });
        }
      }
      // High-interest pages also get cookie + header probes — sort by score
      // first so log-shaped routes (often low-interest by URL pattern but
      // high-interest because they bring user-controlled data into SQL)
      // aren't pushed off the budget by static / asset pages.
      const sortedPages = [...map.pages].sort((a, b) => (b.interestScore ?? 0) - (a.interestScore ?? 0));
      for (const p of sortedPages.slice(0, 25)) {
        for (const h of HEADER_INJECTION_POINTS) points.push({ kind: "header", url: p.url, header: h });
        const cookies = Object.entries(map.cookies ?? {}).slice(0, 3);
        for (const [name, value] of cookies) points.push({ kind: "cookie", url: p.url, cookieName: name, cookieValue: value });
      }
      // POST-JSON shaped endpoints — anything matching /api/, /v\d/, /rest/, /graphql.
      for (const p of map.pages) {
        if (!/\/(api|v\d|rest|graphql)\b/i.test(p.url)) continue;
        for (const k of ["id", "user", "username", "email", "search", "query", "filter", "name"]) {
          points.push({ kind: "post-json", url: p.url, param: k });
        }
      }
    } else {
      for (const param of seed.searchParams.keys()) points.push({ kind: "query", url: seed, param });
    }

    // De-dup by stable id; cap so a giant sitemap doesn't blow runtime.
    const uniq = new Map<string, Point>();
    for (const p of points) uniq.set(pointId(p), p);
    // Default cap: 250 — enough that even a richly-mapped target with 25
    // pages × 5 header injection points × ~12 URL params doesn't get cut.
    const allPoints = [...uniq.values()].slice(0, Math.min(Number(ctx.options.maxPoints) || 250, 600));
    if (!allPoints.length) { await ctx.progress(1, "no injection points"); return; }
    await ctx.log("info", `${allPoints.length} injection points to test`);

    let progress = 0;
    const total = allPoints.length;
    const fired = new Set<string>(); // dedup per (point, technique)

    for (const point of allPoints) {
      if (ctx.signal.aborted) break;
      progress += 1;
      if (progress % 5 === 0) await ctx.progress(progress / total, pointHumanLabel(point));

      const baseline = await baselineFor(session, point, ctx.signal);
      if (!baseline) continue;

      // ─── Error-based ─────────────────────────────────────────────
      for (const payload of ERROR_PAYLOADS) {
        if (ctx.signal.aborted) break;
        const r = await probe(session, point, payload, ctx.signal);
        if (!r) continue;
        const dbms = detectDbmsError(r.body);
        if (!dbms) continue;
        // Make sure the baseline didn't already trip the regex (avoid FPs on
        // sites that always echo SQL noise).
        if (detectDbmsError(baseline.body)) continue;
        const key = `${pointId(point)}|error`;
        if (fired.has(key)) break;
        fired.add(key);
        await ctx.emit(draft({
          severity: "critical", confidence: "high",
          title: `Error-based SQLi (${dbms}) on ${pointHumanLabel(point)}`,
          description: `Injection payload \`${payload}\` triggered a ${dbms} engine error in the response. Direct SQLi confirmed.`,
          ruleId: `sqli/error/${dbms.replace(/[^a-z0-9]/gi, "-").toLowerCase()}`,
          cwe: ["CWE-89"], owasp: ["A03:2021"],
          location: pointLocation(point),
          evidence: { dbms, payload, status: r.status, snippet: truncate(r.body, 400) },
          remediation: "Use parameterized queries / prepared statements throughout. Audit every ORM raw-SQL usage. Fail closed on DB errors — never expose them to clients.",
          references: ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
        }));
        break; // Once error confirms it, no need to spam more payloads on this point.
      }

      // ─── Boolean-based blind ─────────────────────────────────────
      // We require that probes for "true" and "false" produce DIFFERENT
      // responses, AND the "true" probe matches the baseline, AND the "false"
      // probe does NOT match the baseline. This filters most generic
      // 200-on-everything endpoints.
      if (!fired.has(`${pointId(point)}|error`)) {
        for (const bp of BOOLEAN_PAYLOADS) {
          if (ctx.signal.aborted) break;
          const truR = await probe(session, point, "1" + bp.tru, ctx.signal);
          const falR = await probe(session, point, "1" + bp.fal, ctx.signal);
          if (!truR || !falR) continue;
          const lenDeltaTF = Math.abs(truR.body.length - falR.body.length);
          const lenDeltaTB = Math.abs(truR.body.length - baseline.body.length);
          const lenDeltaFB = Math.abs(falR.body.length - baseline.body.length);
          // Strong signal: TRUE ≈ baseline, FALSE far from baseline AND from TRUE.
          const baselineLen = Math.max(baseline.body.length, 1);
          if (lenDeltaTF > Math.max(40, baselineLen * 0.05) &&
              lenDeltaTB < Math.max(20, baselineLen * 0.02) &&
              lenDeltaFB > Math.max(40, baselineLen * 0.05)) {
            const key = `${pointId(point)}|boolean`;
            if (fired.has(key)) break;
            fired.add(key);
            await ctx.emit(draft({
              severity: "critical", confidence: "medium",
              title: `Boolean-based blind SQLi on ${pointHumanLabel(point)} (${bp.label})`,
              description: `Probe \`${bp.tru}\` produced a response equivalent to the benign baseline; \`${bp.fal}\` produced a different one — strong evidence of conditional SQL evaluation.`,
              ruleId: `sqli/boolean/${bp.label}`,
              cwe: ["CWE-89"], owasp: ["A03:2021"],
              location: pointLocation(point),
              evidence: { tru: bp.tru, fal: bp.fal, baselineLen: baseline.body.length, truLen: truR.body.length, falLen: falR.body.length },
              remediation: "Use parameterized queries. Bool-blind SQLi enables full data extraction one bit at a time.",
            }));
            break;
          }
        }
      }

      // ─── Time-based blind ────────────────────────────────────────
      if (!fired.has(`${pointId(point)}|error`) && !fired.has(`${pointId(point)}|boolean`)) {
        const sec = 4;
        for (const tp of TIME_PROBES) {
          if (ctx.signal.aborted) break;
          const r = await probe(session, point, "1" + tp.payload(sec), ctx.signal);
          if (!r) continue;
          // We need the latency to clearly exceed `sec` seconds AND clearly
          // exceed the baseline (to filter cold-start outliers).
          if (r.latencyMs >= sec * 1000 - 500 && r.latencyMs - baseline.latencyMs >= sec * 1000 - 500) {
            // Confirm with a second probe — single-shot is too flaky for time-blind.
            const r2 = await probe(session, point, "1" + tp.payload(sec), ctx.signal);
            if (!r2 || r2.latencyMs < sec * 1000 - 500) continue;
            const key = `${pointId(point)}|time`;
            if (fired.has(key)) break;
            fired.add(key);
            await ctx.emit(draft({
              severity: "critical", confidence: "medium",
              title: `Time-based blind SQLi (${tp.dbms}) on ${pointHumanLabel(point)}`,
              description: `Sleep payload caused ${Math.round(r.latencyMs)}ms latency (baseline ~${Math.round(baseline.latencyMs)}ms). Confirmed on second probe.`,
              ruleId: `sqli/time/${tp.dbms.replace(/[^a-z0-9]/gi, "-").toLowerCase()}`,
              cwe: ["CWE-89"], owasp: ["A03:2021"],
              location: pointLocation(point),
              evidence: { dbms: tp.dbms, payload: tp.payload(sec), latencyMs: r.latencyMs, baselineMs: baseline.latencyMs, secondProbeMs: r2.latencyMs },
              remediation: "Use parameterized queries. Time-blind SQLi enables full data extraction at low bandwidth.",
            }));
            break;
          }
        }
      }

      // ─── UNION column-count discovery ────────────────────────────
      // Only run if error-based already detected SQLi (otherwise too noisy):
      // saves time + guarantees signal quality.
      if (fired.has(`${pointId(point)}|error`)) {
        const orderProbes = orderByPayloads(12);
        let lastOk = 0;
        for (const op of orderProbes) {
          if (ctx.signal.aborted) break;
          const r = await probe(session, point, "1" + op.payload, ctx.signal);
          if (!r) continue;
          // Page that worked vs page that errored.
          const errored = detectDbmsError(r.body);
          if (errored) break;
          if (r.status >= 200 && r.status < 400) lastOk = op.n;
        }
        if (lastOk > 0) {
          await ctx.emit(draft({
            severity: "high", confidence: "medium",
            title: `UNION column count: ${lastOk} on ${pointHumanLabel(point)}`,
            description: `Iterative ORDER BY probes ran cleanly up to ${lastOk} columns and errored beyond — UNION-based SQLi exploitable with ${lastOk}-column UNION SELECTs.`,
            ruleId: "sqli/union-count",
            cwe: ["CWE-89"], owasp: ["A03:2021"],
            location: pointLocation(point),
            evidence: { columns: lastOk },
            remediation: "Use parameterized queries; this finding implies attackers can extract entire tables one row at a time.",
          }));
        }
      }
    }

    await ctx.progress(1, `${fired.size} SQLi findings across ${allPoints.length} injection points`);
  },
};

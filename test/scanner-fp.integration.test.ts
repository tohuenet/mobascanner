/**
 * End-to-end false-positive regression tests. These drive the REAL scanners
 * (param-miner, sqli) through their full run() against local mock servers that
 * reproduce the exact behaviors that produced the scribd.com false-positive
 * flood — and assert ZERO findings. Paired true-positive mocks prove the fixes
 * did not simply disable detection.
 *
 *   FP-1  URL-echo homepage  → param-miner must emit nothing (negative control
 *         sees the echo and refuses to attribute reflection to any param).
 *   TP-1  param reflected only for a specific name → param-miner must find it.
 *   FP-2  jittery body + blocked FALSE probe → sqli boolean-blind emits nothing.
 *   TP-2  genuine conditional (true≈baseline, false shorter, deterministic) →
 *         sqli must emit a boolean-blind finding.
 */
import { test } from "node:test";
import assert from "node:assert";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { paramMinerScanner } from "../lib/scanners/web/param-miner";
import { sqliScanner } from "../lib/scanners/web/sqli";
import { sstiScanner } from "../lib/scanners/web/advanced-injection";
import type { ScanContext } from "../lib/engine/scanner";
import type { Finding } from "../lib/types";

type Draft = Omit<Finding, "id" | "scanId" | "scannerId" | "scannerName" | "createdAt">;

function harness(targetUrl: string, options: Record<string, unknown> = {}) {
  const findings: Draft[] = [];
  const ctx: ScanContext = {
    // A scanId with no sitemap on disk → scanners fall back to the seed URL.
    scanId: "fp-regression-no-sitemap",
    target: { value: targetUrl, type: "url" },
    options,
    signal: new AbortController().signal,
    emit: async (d) => { findings.push(d); },
    log: async () => {},
    progress: async () => {},
    discover: () => true,
  };
  return { ctx, findings };
}

async function listen(handler: http.RequestListener): Promise<{ base: string; close: () => Promise<void> }> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  return { base, close: () => new Promise<void>((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

test("FP: URL-echo homepage yields zero param-miner findings", { timeout: 30_000 }, async () => {
  // Echoes the request URL (incl. query) once — like a Next.js canonical/og:url.
  // Any canary "reflects" for ANY param name, so a naive miner reports dozens of
  // hidden params. The negative control must catch this.
  const { base, close } = await listen((req, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<!doctype html><html><head><link rel="canonical" href="https://site${req.url}"></head><body>${"padding ".repeat(400)}</body></html>`);
  });
  try {
    const { ctx, findings } = harness(base);
    await paramMinerScanner.run(ctx);
    assert.strictEqual(findings.length, 0, `expected 0 findings, got ${findings.length}: ${findings.map((f) => f.title).join("; ")}`);
  } finally {
    await close();
  }
});

test("TP: a genuinely reflected hidden parameter is still found", { timeout: 30_000 }, async () => {
  // Reflects ONLY the `debug` param's value; the URL is NOT echoed generally, so
  // the random control stays silent and the finding is attributable.
  const { base, close } = await listen((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const debug = u.searchParams.get("debug");
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    let body = `<!doctype html><html><body>Stable home ${"x".repeat(500)}`;
    if (debug) body += `<!-- debug=${debug} -->`;
    res.end(body + `</body></html>`);
  });
  try {
    const { ctx, findings } = harness(base);
    await paramMinerScanner.run(ctx);
    const debugHit = findings.filter((f) => /"debug"/.test(f.title));
    assert.strictEqual(debugHit.length, 1, `expected exactly the debug param, got: ${findings.map((f) => f.title).join("; ") || "none"}`);
    assert.strictEqual(debugHit[0].ruleId, "param-miner/canary-reflected");
  } finally {
    await close();
  }
});

test("FP: jittery body + blocked FALSE probe yields zero sqli boolean findings", { timeout: 30_000 }, async () => {
  // Body length varies wildly per request (dynamic page), and any `1=2`-style
  // probe is dropped to an empty 200 (WAF-ish). The old detector read the empty
  // FALSE response as "SQL evaluated false" → critical FP.
  let n = 0;
  const { base, close } = await listen((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const q = u.searchParams.get("q") ?? "";
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    if (/1=2|'1'='2|"1"="2|\(1=2/.test(q)) { res.end(""); return; } // blocked/empty
    n += 1;
    res.end("A".repeat(4000 + ((n * 1373) % 9000))); // heavy jitter
  });
  try {
    const { ctx, findings } = harness(`${base}?q=1`);
    await sqliScanner.run(ctx);
    const bool = findings.filter((f) => (f.ruleId ?? "").startsWith("sqli/boolean"));
    assert.strictEqual(bool.length, 0, `expected 0 boolean-blind SQLi, got ${bool.length}`);
  } finally {
    await close();
  }
});

test("TP: a genuine boolean-blind SQLi is still detected", { timeout: 30_000 }, async () => {
  // Deterministic conditional: TRUE (and everything benign) → long body,
  // FALSE (`1=2`) → short but NON-empty body. Reproduces on re-probe.
  const { base, close } = await listen((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const q = u.searchParams.get("q") ?? "";
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    const isFalse = /1=2|'1'='2|"1"="2|\(1=2/.test(q);
    res.end(isFalse ? "row".repeat(50) : "row".repeat(2000)); // short vs long, both non-empty, stable
  });
  try {
    const { ctx, findings } = harness(`${base}?q=1`);
    await sqliScanner.run(ctx);
    const bool = findings.filter((f) => (f.ruleId ?? "").startsWith("sqli/boolean"));
    assert.ok(bool.length >= 1, `expected a boolean-blind SQLi finding, got: ${findings.map((f) => f.ruleId).join("; ") || "none"}`);
    assert.strictEqual(bool[0].severity, "critical");
  } finally {
    await close();
  }
});

test("FP: a page that naturally contains 1337 yields zero SSTI findings", { timeout: 30_000 }, async () => {
  // The value the arithmetic probes look for (7*191=1337) appears naturally —
  // a port, a view-count, leetspeak. The param value is reflected but NOT
  // evaluated. Old code fired a critical SSTI on every param.
  const { base, close } = await listen((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<html><body>Elite score 1337. You searched: ${u.searchParams.get("q") ?? ""}</body></html>`);
  });
  try {
    const { ctx, findings } = harness(`${base}?q=1`);
    await sstiScanner.run(ctx);
    const ssti = findings.filter((f) => (f.ruleId ?? "").startsWith("ssti/"));
    assert.strictEqual(ssti.length, 0, `expected 0 SSTI, got ${ssti.length}`);
  } finally {
    await close();
  }
});

test("TP: a template engine that evaluates 7*191 is still detected", { timeout: 30_000 }, async () => {
  // Emulates a template engine: the arithmetic payloads evaluate to 1337; a
  // benign value does not. So the baseline (no 1337) → probe (1337) is attributable.
  const EVAL = /\{\{\s*7\s*\*\s*191\s*\}\}|\$\{\s*7\s*\*\s*191\s*\}|<%=\s*7\s*\*\s*191\s*%>|#set\(\$x=7\*191\)\$x|@\(7\*191\)|\{math equation="7\*191"\}/g;
  const { base, close } = await listen((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const q = u.searchParams.get("q") ?? "";
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<html><body>result: ${q.replace(EVAL, "1337")}</body></html>`);
  });
  try {
    const { ctx, findings } = harness(`${base}?q=1`);
    await sstiScanner.run(ctx);
    const ssti = findings.filter((f) => (f.ruleId ?? "").startsWith("ssti/"));
    assert.ok(ssti.length >= 1, `expected an SSTI finding, got: ${findings.map((f) => f.ruleId).join("; ") || "none"}`);
    assert.strictEqual(ssti[0].severity, "critical");
  } finally {
    await close();
  }
});

/**
 * Plausibility self-audit tests — the non-destructive backstop that warns when
 * a scanner emits a false-positive-shaped burst of high/critical findings.
 */
import { test } from "node:test";
import assert from "node:assert";
import { auditFindings } from "../lib/engine/plausibility";
import type { Finding, Severity } from "../lib/types";

function mk(scannerId: string, severity: Severity, i: number, url = `https://x.com/${i}`): Finding {
  return {
    id: `f${i}`, scanId: "s", scannerId, scannerName: scannerId,
    severity, confidence: "medium", title: `t${i}`, description: "",
    location: { url }, createdAt: 0,
  };
}

test("auditFindings: warns on a 19-critical burst from one scanner", () => {
  const findings = Array.from({ length: 19 }, (_, i) => mk("web.sqli", "critical", i));
  const w = auditFindings(findings);
  assert.strictEqual(w.length, 1);
  assert.strictEqual(w[0].scannerId, "web.sqli");
  assert.strictEqual(w[0].severity, "critical");
  assert.strictEqual(w[0].count, 19);
});

test("auditFindings: silent on a small, realistic cluster", () => {
  const findings = [
    mk("web.sqli", "critical", 1),
    mk("web.cookies", "high", 2),
    mk("web.cookies", "high", 3),
    ...Array.from({ length: 40 }, (_, i) => mk("web.sri", "low", i)), // low sev — ignored
  ];
  assert.deepStrictEqual(auditFindings(findings), []);
});

test("auditFindings: reports distinct scanner/severity buckets separately", () => {
  const findings = [
    ...Array.from({ length: 14 }, (_, i) => mk("web.param-miner", "high", i)),
    ...Array.from({ length: 13 }, (_, i) => mk("web.sqli", "critical", 100 + i)),
  ];
  const w = auditFindings(findings).sort((a, b) => a.scannerId.localeCompare(b.scannerId));
  assert.strictEqual(w.length, 2);
  assert.strictEqual(w[0].scannerId, "web.param-miner");
  assert.strictEqual(w[1].scannerId, "web.sqli");
});

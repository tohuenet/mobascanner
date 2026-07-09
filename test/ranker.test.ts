/**
 * Regression tests for the heuristic ranker
 * (`lib/triage/ranker.ts` → `rankFindings`).
 *
 * The ranker drives the "fix this week" panel, so the ordering contract
 * (descending score, 1-based ranks, active/critical over passive/info) matters.
 */
import { test } from "node:test";
import assert from "node:assert";
import { rankFindings } from "../lib/triage/ranker";
import { makeFinding } from "./_factory";

test("rankFindings: sorts by descending score with 1-based ranks, active/critical first", () => {
  const critical = makeFinding({
    id: "crit",
    severity: "critical",
    confidence: "high",
    ruleId: "sqli/error-based", // matches ACTIVE_RULES → exploitability 1.0
    scannerId: "web.sqli",
    location: { url: "https://target.test/q" },
  });
  const middle = makeFinding({
    id: "mid",
    severity: "high",
    confidence: "medium",
    ruleId: "misc/thing", // neither active nor passive → exploitability 0.7
    scannerId: "web.misc",
    location: { url: "https://target.test/x" },
  });
  const passive = makeFinding({
    id: "pass",
    severity: "info",
    confidence: "low",
    ruleId: "headers/csp", // matches PASSIVE_RULES → exploitability 0.4
    scannerId: "web.headers",
    location: { url: "https://target.test/y" },
  });

  // Feed them out of order to prove the ranker actually sorts.
  const ranked = rankFindings([passive, critical, middle]);

  assert.strictEqual(ranked.length, 3);
  // Ranks are 1-based and follow output order.
  assert.deepStrictEqual(ranked.map((r) => r.rank), [1, 2, 3]);
  // Scores are non-increasing.
  for (let i = 1; i < ranked.length; i++) {
    assert.ok(ranked[i - 1].score >= ranked[i].score, "scores are descending");
  }
  // The critical/high-confidence active finding outranks the info/passive one.
  assert.strictEqual(ranked[0].id, "crit");
  assert.strictEqual(ranked[0].finding.id, "crit");
  assert.strictEqual(ranked[2].id, "pass");
});

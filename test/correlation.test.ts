/**
 * Regression tests for the cross-surface correlation engine
 * (`lib/correlation/engine.ts` → `correlateFindings`).
 *
 * Locks in the product's competitive wedge: DAST↔SAST/SCA joins, and — most
 * importantly — the BROWSER_LIBS gate that stops us from deprioritizing a
 * backend dependency just because a frontend fingerprint never saw it.
 */
import { test } from "node:test";
import assert from "node:assert";
import { correlateFindings } from "../lib/correlation/engine";
import type { Finding } from "../lib/types";
import { makeFinding } from "./_factory";

/** Pull a string[] out of an `unknown` evidence field without using `any`. */
function strArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

test("correlateFindings: empty input yields empty output", () => {
  assert.deepStrictEqual(correlateFindings([]), []);
});

test("correlateFindings: CVE cross-surface join links a web + source finding on a shared CVE", () => {
  const web = makeFinding({
    id: "web-cve-1",
    scannerId: "web.cve-pack",
    scannerName: "Web CVE Pack",
    severity: "high",
    confidence: "high",
    title: "Log4Shell reachable on the running app",
    cve: ["CVE-2021-44228"],
    location: { url: "https://app.example.com/" },
  });
  const source = makeFinding({
    id: "src-cve-1",
    scannerId: "source.trivy",
    scannerName: "Trivy",
    severity: "high",
    confidence: "high",
    title: "log4j-core is vulnerable",
    cve: ["CVE-2021-44228"],
    evidence: { pkg: "log4j-core", installed: "2.14.0" },
    location: { file: "pom.xml" },
  });

  const result = correlateFindings([web, source]);

  assert.strictEqual(result.length, 1);
  const f = result[0];
  assert.strictEqual(f.ruleId, "correlation/cve-cross-surface");
  assert.strictEqual(f.evidence?.crossSurface, true);
  const contrib = strArray(f.evidence?.contributingFindings);
  assert.ok(contrib.includes("web-cve-1"), "references the web finding");
  assert.ok(contrib.includes("src-cve-1"), "references the source finding");
});

test("correlateFindings: version-reachable join escalates a live-served vulnerable dep", () => {
  const source = makeFinding({
    id: "src-lodash",
    scannerId: "source.trivy",
    scannerName: "Trivy",
    severity: "high",
    confidence: "high",
    title: "lodash prototype pollution",
    evidence: { pkg: "lodash", installed: "4.17.4" },
    location: { file: "package.json" },
  });
  const web = makeFinding({
    id: "web-fp",
    scannerId: "web.fingerprint",
    scannerName: "Tech Fingerprint",
    severity: "low",
    confidence: "medium",
    title: "Live library/runtime versions",
    evidence: { liveVersions: [{ pkg: "lodash", version: "4.17.4", ecosystem: "npm" }] },
    location: { url: "https://app.example.com/" },
  });

  const result = correlateFindings([source, web]);

  assert.strictEqual(result.length, 1);
  const f = result[0];
  assert.strictEqual(f.ruleId, "correlation/version-reachable");
  assert.strictEqual(f.severity, "critical"); // "high" bumped one bucket on confirmation
  assert.strictEqual(f.evidence?.crossSurface, true);
});

test("correlateFindings: not-observed hint fires ONLY for browser libs (backend/other excluded)", () => {
  // jQuery genuinely ships to the browser → a runtime miss is a meaningful hint.
  const jquery = makeFinding({
    id: "src-jquery",
    scannerId: "source.trivy",
    severity: "high",
    title: "jquery XSS",
    evidence: { pkg: "jquery", installed: "3.4.0" },
    location: { file: "package.json" },
  });
  // express is a backend Node dep in the SAME package.json → invisible to a
  // frontend fingerprint, so "not observed" is NOT evidence of absence.
  const express = makeFinding({
    id: "src-express",
    scannerId: "source.trivy",
    severity: "high",
    title: "express open redirect",
    evidence: { pkg: "express", installed: "4.17.0" },
    location: { file: "package.json" },
  });
  // rack is a Ruby gem (server-side, non-JS manifest) → never deprioritized.
  const rack = makeFinding({
    id: "src-rack",
    scannerId: "source.trivy",
    severity: "high",
    title: "rack vulnerability",
    evidence: { pkg: "rack", installed: "2.2.3" },
    location: { file: "Gemfile.lock" },
  });
  // A live fingerprint that omits all three, so the version join runs
  // (live.size > 0) but none of the packages above are observed at runtime.
  const web = makeFinding({
    id: "web-fp",
    scannerId: "web.fingerprint",
    title: "Live library/runtime versions",
    evidence: { liveVersions: [{ pkg: "react", version: "18.2.0", ecosystem: "npm" }] },
    location: { url: "https://app.example.com/" },
  });

  const result = correlateFindings([jquery, express, rack, web]);

  const notObserved = result.filter((f) => f.ruleId === "correlation/not-observed-at-runtime");
  assert.strictEqual(notObserved.length, 1, "exactly one not-observed hint");
  assert.strictEqual(notObserved[0].evidence?.pkg, "jquery");

  // Anti-false-positive guard: neither the backend Node dep nor the Ruby gem
  // may produce ANY finding.
  const pkgs = result.map((f) => f.evidence?.pkg);
  assert.ok(!pkgs.includes("express"), "express (backend Node) must not produce a finding");
  assert.ok(!pkgs.includes("rack"), "rack (Ruby gem) must not produce a finding");
});

test("correlateFindings: idempotent — the same union yields an identical set of ids", () => {
  const union: Finding[] = [
    makeFinding({
      id: "w1",
      scannerId: "web.cve-pack",
      severity: "high",
      cve: ["CVE-2021-44228"],
      location: { url: "https://app.example.com/" },
    }),
    makeFinding({
      id: "s1",
      scannerId: "source.trivy",
      severity: "high",
      cve: ["CVE-2021-44228"],
      evidence: { pkg: "log4j-core", installed: "2.14.0" },
      location: { file: "pom.xml" },
    }),
    makeFinding({
      id: "w2",
      scannerId: "web.fingerprint",
      evidence: { liveVersions: [{ pkg: "lodash", version: "4.17.4", ecosystem: "npm" }] },
      location: { url: "https://app.example.com/" },
    }),
    makeFinding({
      id: "s2",
      scannerId: "source.trivy",
      severity: "high",
      evidence: { pkg: "lodash", installed: "4.17.4" },
      location: { file: "package.json" },
    }),
  ];

  const ids1 = correlateFindings(union).map((f) => f.id).sort();
  const ids2 = correlateFindings(union).map((f) => f.id).sort();

  assert.ok(ids1.length >= 2, "expected multiple correlated findings");
  assert.deepStrictEqual(ids1, ids2);
});

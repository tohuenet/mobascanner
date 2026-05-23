/**
 * Chain detection — combine raw findings into composite "this is the actual
 * exploit path" findings.
 *
 * Every chain rule is just a predicate over a Finding[] that returns 0+
 * synthetic Findings ("composite"). Runs after all scanners complete.
 *
 * Goal: turn a wall of medium-severity dots into a few critical-severity
 * exploit narratives — the same way a human pentester would write the
 * report.
 */

import { randomUUID } from "node:crypto";
import { draft } from "../engine/scanner";
import type { Finding, Severity } from "../types";

interface ChainRule {
  id: string;
  name: string;
  describe: string;
  detect(findings: Finding[]): Array<{
    severity: Severity;
    title: string;
    description: string;
    refs: string[]; // ids of contributing findings
    location?: { url?: string; file?: string };
    cwe?: string[];
    owasp?: string[];
  }>;
}

const has = (findings: Finding[], pred: (f: Finding) => boolean) => findings.find(pred);
const all = (findings: Finding[], pred: (f: Finding) => boolean) => findings.filter(pred);

const RULES: ChainRule[] = [
  // ── XSS + missing HttpOnly cookie → session hijack ───────────
  {
    id: "chain/xss-cookie-hijack",
    name: "XSS + JS-readable session cookie",
    describe: "Reflected XSS plus a session/auth cookie missing HttpOnly means session hijack is one click away.",
    detect(fs) {
      const xss = has(fs, (f) => f.ruleId === "xss/reflected" || /xss/i.test(f.title));
      const cookie = has(fs, (f) => f.ruleId === "cookies/httponly");
      if (!xss || !cookie) return [];
      return [{
        severity: "critical",
        title: "Chain: reflected XSS + session cookie without HttpOnly",
        description: "A reflected XSS sink was found, AND a session/auth cookie is JS-readable. Together these allow stealing the session in one click — full account takeover.",
        refs: [xss.id, cookie.id],
        location: xss.location,
        cwe: ["CWE-79", "CWE-1004"],
        owasp: ["A03:2021", "A07:2021"],
      }];
    },
  },

  // ── SSRF + AWS metadata reachable ────────────────────────────
  {
    id: "chain/ssrf-aws-imds",
    name: "SSRF reaches AWS IMDS",
    describe: "Server-side request forgery plus a response that contains AWS instance metadata = credential theft.",
    detect(fs) {
      const ssrf = has(fs, (f) => f.ruleId === "ssrf/aws-imds");
      if (!ssrf) return [];
      return [{
        severity: "critical",
        title: "Chain: SSRF leaks AWS instance credentials",
        description: "Server fetched our SSRF probe URL AND returned IMDS data — temporary IAM credentials are in scope. Treat as a confirmed cloud breach.",
        refs: [ssrf.id],
        location: ssrf.location,
        cwe: ["CWE-918"],
        owasp: ["A10:2021"],
      }];
    },
  },

  // ── Open admin panel + default-cred-shaped paths ─────────────
  {
    id: "chain/admin-exposed",
    name: "Admin panel exposed",
    describe: "Admin / mgmt path reachable without auth gate.",
    detect(fs) {
      const adminHits = all(fs, (f) => {
        if (!f.ruleId?.startsWith("content-discovery/")) return false;
        if (!/admin|wp-admin|wp-login|adminer|phpmyadmin|manager\/html|jenkins|grafana/i.test(f.location.url ?? "")) return false;
        if (f.severity === "info") return false;
        if (f.title.includes("auth-gated")) return false;
        // Defense-in-depth: only chain off a genuinely reachable 2xx. The
        // upstream scanner now filters catch-all redirects (308 trailing-slash
        // normalization, SPA 404 shells), but if a 3xx ever leaks through we
        // must not escalate it to "admin panel reachable without auth".
        const status = typeof f.evidence?.status === "number" ? (f.evidence.status as number) : undefined;
        if (status !== undefined && (status < 200 || status >= 300)) return false;
        return true;
      });
      if (!adminHits.length) return [];
      return adminHits.map((a) => ({
        severity: "high" as Severity,
        title: `Chain: admin panel reachable without auth — ${a.location.url}`,
        description: "Admin / management interface returns content without an auth challenge. Combine with default-credential brute-force or a dependency CVE for full compromise.",
        refs: [a.id],
        location: a.location,
        cwe: ["CWE-284"],
        owasp: ["A01:2021"],
      }));
    },
  },

  // ── Dep CVE + secret nearby = real stake ─────────────────────
  {
    id: "chain/cve-plus-secret",
    name: "CVE in deps + nearby hardcoded secret",
    describe: "When a critical-CVE dep ships in the same checkout as hardcoded API keys, that's the headline.",
    detect(fs) {
      const cves = all(fs, (f) => Array.isArray(f.cve) && f.cve.length > 0 && (f.severity === "critical" || f.severity === "high"));
      const secrets = all(fs, (f) => f.scannerId === "source.regex-secrets" || f.scannerId === "source.gitleaks" || f.scannerId === "source.trufflehog");
      if (!cves.length || !secrets.length) return [];
      return [{
        severity: "high",
        title: `Chain: ${cves.length} high/critical CVE${cves.length === 1 ? "" : "s"} co-exist with ${secrets.length} hardcoded secret${secrets.length === 1 ? "" : "s"} in the repo`,
        description: "The blast-radius of unpatched deps is amplified by hardcoded credentials in the same codebase. A successful RCE via a dep CVE inherits the secrets verbatim.",
        refs: [...cves.slice(0, 3).map((c) => c.id), ...secrets.slice(0, 3).map((s) => s.id)],
        cwe: ["CWE-1395"],
        owasp: ["A06:2021", "A07:2021"],
      }];
    },
  },

  // ── DB port exposed + .env exposed ───────────────────────────
  {
    id: "chain/db-port-plus-env",
    name: "DB port open + env leak",
    describe: "DB port reachable plus a leaked .env with creds = direct DB compromise.",
    detect(fs) {
      const dbPort = has(fs, (f) =>
        f.scannerId === "web.ports" &&
        /mysql|postgres|mongodb|redis|mssql|memcached|elasticsearch/.test(f.title.toLowerCase()));
      const envLeak = has(fs, (f) =>
        (f.ruleId?.startsWith("content-discovery/") && /\.env/.test(f.location.url ?? "")) ||
        f.ruleId === "secret/aws-secret-key" ||
        f.ruleId === "secret/generic-password-url");
      if (!dbPort || !envLeak) return [];
      return [{
        severity: "critical",
        title: "Chain: database port reachable AND credentials leaked",
        description: "An exposed DB port + leaked credentials is a direct path to full DB read/write. Rotate creds immediately, restrict the port to private networks.",
        refs: [dbPort.id, envLeak.id],
        location: dbPort.location,
        cwe: ["CWE-200", "CWE-798"],
        owasp: ["A05:2021", "A07:2021"],
      }];
    },
  },

  // ── Missing CSRF + cookie SameSite=None or missing ───────────
  {
    id: "chain/csrf-samesite",
    name: "CSRF risk: form unprotected + cookie SameSite weak",
    describe: "POST form without CSRF token + session cookie without SameSite restriction.",
    detect(fs) {
      const csrf = has(fs, (f) => f.ruleId === "crawler/missing-csrf");
      const sameSite = has(fs, (f) => f.ruleId === "cookies/samesite" || f.ruleId === "cookies/samesite-none-insecure");
      if (!csrf || !sameSite) return [];
      return [{
        severity: "high",
        title: "Chain: state-changing form with no CSRF token AND weak SameSite",
        description: "POST form lacks an anti-CSRF token AND the auth cookie does not pin to first-party context. A cross-origin POST will be authenticated and accepted.",
        refs: [csrf.id, sameSite.id],
        location: csrf.location,
        cwe: ["CWE-352"],
        owasp: ["A01:2021"],
      }];
    },
  },

  // ── GraphQL introspection + auth missing ─────────────────────
  {
    id: "chain/graphql-introspection-public",
    name: "GraphQL introspection on public endpoint",
    describe: "Introspection schema dump from an unauthenticated endpoint is a full-API recon win.",
    detect(fs) {
      const intro = has(fs, (f) => f.ruleId === "graphql/introspection");
      if (!intro) return [];
      return [{
        severity: "high",
        title: "Chain: GraphQL introspection on a publicly reachable endpoint",
        description: "Attackers now have your full API surface (queries, mutations, types). Pair with BOLA / mass-assignment fuzzing to land a real exploit.",
        refs: [intro.id],
        location: intro.location,
        cwe: ["CWE-200"],
        owasp: ["A05:2021"],
      }];
    },
  },
];

/** Run all chain rules and produce composite Findings. */
export function detectChains(scanId: string, findings: Finding[]): Finding[] {
  const out: Finding[] = [];
  for (const rule of RULES) {
    const composites = rule.detect(findings);
    for (const c of composites) {
      out.push({
        ...draft({
          severity: c.severity,
          confidence: "high",
          title: c.title,
          description: c.description,
          ruleId: rule.id,
          cwe: c.cwe,
          owasp: c.owasp,
          location: c.location ?? {},
          evidence: { contributingFindings: c.refs, ruleName: rule.name, ruleDescription: rule.describe },
          remediation: "Treat this as the priority finding. Fix the chain by addressing any one link — but ideally all of them.",
        }),
        id: randomUUID(),
        scanId,
        scannerId: "chain",
        scannerName: "Chain Detection",
        createdAt: Date.now(),
      });
    }
  }
  return out;
}

export const CHAIN_RULE_SUMMARIES = RULES.map((r) => ({ id: r.id, name: r.name, describe: r.describe }));

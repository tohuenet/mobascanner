/**
 * Compliance mapping — turn the normalized findings stream into a
 * compliance-control gap report.
 *
 * Frameworks supported:
 *   - PCI-DSS v4.0
 *   - SOC 2 (Trust Services Criteria, focused on Security)
 *   - HIPAA Security Rule
 *   - ISO 27001:2022 Annex A
 *
 * Mapping is by CWE / OWASP Top-10 code → control id. Multiple controls per
 * finding is normal. The report aggregates findings under each control.
 *
 * Why this is useful: enterprises spend weeks before each audit compiling
 * "evidence we tested for X". Auto-mapping every scan to controls removes
 * that work — and surfaces controls that have ZERO testing coverage.
 */

import type { Finding } from "../types";

export type Framework = "PCI-DSS" | "SOC2" | "HIPAA" | "ISO27001";

interface Mapping {
  /** A CWE id (e.g. "CWE-79") or an OWASP code (e.g. "A03:2021"). */
  match: string;
  /** The framework + control id this matches. */
  controls: { framework: Framework; control: string; description: string }[];
}

const MAPPINGS: Mapping[] = [
  { match: "CWE-79", controls: [
    { framework: "PCI-DSS", control: "6.2.4", description: "Address common application coding vulnerabilities (XSS)." },
    { framework: "SOC2",    control: "CC6.1", description: "Logical access controls protect data and systems." },
    { framework: "HIPAA",   control: "164.312(c)(1)", description: "Mechanism to protect data integrity." },
    { framework: "ISO27001",control: "A.8.28", description: "Secure coding." },
  ] },
  { match: "CWE-89", controls: [
    { framework: "PCI-DSS", control: "6.2.4", description: "Address common application coding vulnerabilities (SQLi)." },
    { framework: "SOC2",    control: "CC7.1", description: "System monitors for vulnerabilities." },
    { framework: "ISO27001",control: "A.8.28", description: "Secure coding." },
  ] },
  { match: "CWE-22", controls: [
    { framework: "PCI-DSS", control: "6.2.4", description: "Address common application coding vulnerabilities (path traversal)." },
    { framework: "ISO27001",control: "A.8.28", description: "Secure coding." },
  ] },
  { match: "CWE-78", controls: [
    { framework: "PCI-DSS", control: "6.2.4", description: "Command injection prevention." },
    { framework: "SOC2",    control: "CC6.6", description: "Restrict logical access to system." },
    { framework: "ISO27001",control: "A.8.28", description: "Secure coding." },
  ] },
  { match: "CWE-94", controls: [
    { framework: "PCI-DSS", control: "6.2.4", description: "Code injection prevention." },
    { framework: "ISO27001",control: "A.8.28", description: "Secure coding." },
  ] },
  { match: "CWE-918", controls: [
    { framework: "PCI-DSS", control: "1.2.1", description: "Restrict inbound and outbound traffic (SSRF)." },
    { framework: "SOC2",    control: "CC6.1", description: "Logical access controls." },
    { framework: "ISO27001",control: "A.8.22", description: "Segregation of networks." },
  ] },
  { match: "CWE-352", controls: [
    { framework: "PCI-DSS", control: "6.2.4", description: "CSRF prevention." },
  ] },
  { match: "CWE-287", controls: [
    { framework: "PCI-DSS", control: "8.3", description: "Strong authentication for users and admins." },
    { framework: "SOC2",    control: "CC6.1", description: "Logical access controls." },
    { framework: "HIPAA",   control: "164.312(d)", description: "Person or entity authentication." },
    { framework: "ISO27001",control: "A.8.5", description: "Secure authentication." },
  ] },
  { match: "CWE-285", controls: [
    { framework: "PCI-DSS", control: "7.2", description: "Restrict access to system components based on need to know." },
    { framework: "SOC2",    control: "CC6.3", description: "Authorization based on roles." },
    { framework: "HIPAA",   control: "164.312(a)(1)", description: "Access control." },
    { framework: "ISO27001",control: "A.5.15", description: "Access control." },
  ] },
  { match: "CWE-639", controls: [
    { framework: "PCI-DSS", control: "7.2", description: "Object-level access control (IDOR)." },
    { framework: "SOC2",    control: "CC6.3", description: "Authorization." },
    { framework: "ISO27001",control: "A.5.15", description: "Access control." },
  ] },
  { match: "CWE-863", controls: [
    { framework: "PCI-DSS", control: "7.2", description: "Incorrect authorization." },
    { framework: "SOC2",    control: "CC6.3", description: "Authorization." },
    { framework: "HIPAA",   control: "164.312(a)(1)", description: "Access control." },
  ] },
  { match: "CWE-798", controls: [
    { framework: "PCI-DSS", control: "8.6", description: "Account credentials must not be hardcoded." },
    { framework: "SOC2",    control: "CC6.1", description: "Logical access controls." },
    { framework: "ISO27001",control: "A.8.5", description: "Secure authentication." },
  ] },
  { match: "CWE-321", controls: [
    { framework: "PCI-DSS", control: "8.3.6", description: "Use of strong cryptographic keys." },
    { framework: "ISO27001",control: "A.8.24", description: "Use of cryptography." },
  ] },
  { match: "CWE-347", controls: [
    { framework: "PCI-DSS", control: "8.3", description: "Authentication integrity (signature verification)." },
    { framework: "ISO27001",control: "A.8.24", description: "Use of cryptography." },
  ] },
  { match: "CWE-319", controls: [
    { framework: "PCI-DSS", control: "4.2", description: "Strong cryptography for transmission." },
    { framework: "SOC2",    control: "CC6.7", description: "Encryption in transit." },
    { framework: "HIPAA",   control: "164.312(e)(1)", description: "Transmission security." },
    { framework: "ISO27001",control: "A.8.24", description: "Cryptography." },
  ] },
  { match: "CWE-326", controls: [
    { framework: "PCI-DSS", control: "4.2", description: "Strong TLS configuration." },
    { framework: "SOC2",    control: "CC6.7", description: "Encryption in transit." },
  ] },
  { match: "CWE-200", controls: [
    { framework: "PCI-DSS", control: "3.5.1", description: "Limit information disclosure." },
    { framework: "SOC2",    control: "CC6.1", description: "Restrict data exposure." },
    { framework: "HIPAA",   control: "164.312(c)(1)", description: "Data integrity." },
  ] },
  { match: "CWE-1004", controls: [
    { framework: "PCI-DSS", control: "8.3.7", description: "Session management — HttpOnly cookie." },
  ] },
  { match: "CWE-614", controls: [
    { framework: "PCI-DSS", control: "4.2", description: "Strong cryptography in cookie transport." },
  ] },
  { match: "CWE-942", controls: [
    { framework: "PCI-DSS", control: "1.4", description: "CORS misconfiguration is a network access control failure." },
  ] },
  { match: "CWE-502", controls: [
    { framework: "PCI-DSS", control: "6.2.4", description: "Insecure deserialization." },
    { framework: "ISO27001",control: "A.8.28", description: "Secure coding." },
  ] },
  { match: "CWE-611", controls: [
    { framework: "PCI-DSS", control: "6.2.4", description: "XML external entity prevention." },
  ] },
  { match: "CWE-444", controls: [
    { framework: "PCI-DSS", control: "1.2", description: "Network smuggling/cache poisoning protections." },
  ] },
  { match: "CWE-829", controls: [
    { framework: "PCI-DSS", control: "6.3.2", description: "Inventory of bespoke and third-party software components." },
    { framework: "ISO27001",control: "A.8.30", description: "Outsourced development." },
  ] },
  { match: "CWE-1395", controls: [
    { framework: "PCI-DSS", control: "6.3.3", description: "Vulnerable components must be patched." },
    { framework: "ISO27001",control: "A.8.8", description: "Management of technical vulnerabilities." },
  ] },
  { match: "A05:2021", controls: [
    { framework: "PCI-DSS", control: "2.2", description: "Secure configurations applied to all system components." },
    { framework: "SOC2",    control: "CC6.1", description: "Configuration management." },
    { framework: "HIPAA",   control: "164.308(a)(1)(ii)(B)", description: "Risk management." },
  ] },
  { match: "A06:2021", controls: [
    { framework: "PCI-DSS", control: "6.3.3", description: "Patch known vulnerabilities." },
    { framework: "ISO27001",control: "A.8.8", description: "Vulnerability management." },
  ] },
  { match: "A07:2021", controls: [
    { framework: "PCI-DSS", control: "8", description: "Identification and authentication." },
    { framework: "HIPAA",   control: "164.312(d)", description: "Person/entity authentication." },
    { framework: "ISO27001",control: "A.8.5", description: "Secure authentication." },
  ] },
  { match: "A09:2021", controls: [
    { framework: "PCI-DSS", control: "10.2", description: "Audit logs implemented." },
    { framework: "SOC2",    control: "CC7.2", description: "System monitors and detects security events." },
    { framework: "ISO27001",control: "A.8.15", description: "Logging." },
  ] },
  { match: "A10:2021", controls: [
    { framework: "PCI-DSS", control: "1.2", description: "Restrict outbound traffic to prevent SSRF." },
  ] },
];

export interface ComplianceReport {
  framework: Framework;
  controls: Array<{
    control: string;
    description: string;
    findings: number;
    severityCounts: Record<string, number>;
    sampleFindings: Array<{ id: string; title: string; severity: string }>;
  }>;
  uncoveredControls: string[];
  totalFindings: number;
}

const ALL_CONTROLS: Record<Framework, string[]> = {
  "PCI-DSS": ["1.2", "1.4", "2.2", "3.5.1", "4.2", "6.2.4", "6.3.2", "6.3.3", "7.2", "8", "8.3", "8.3.6", "8.3.7", "8.6", "10.2"],
  "SOC2":    ["CC6.1", "CC6.3", "CC6.6", "CC6.7", "CC7.1", "CC7.2"],
  "HIPAA":   ["164.308(a)(1)(ii)(B)", "164.312(a)(1)", "164.312(c)(1)", "164.312(d)", "164.312(e)(1)"],
  "ISO27001":["A.5.15", "A.8.5", "A.8.8", "A.8.15", "A.8.22", "A.8.24", "A.8.28", "A.8.30"],
};

/** Get the controls a finding maps to. A finding can hit multiple. */
function controlsFor(f: Finding): { framework: Framework; control: string; description: string }[] {
  const keys = [...(f.cwe ?? []), ...(f.owasp ?? [])];
  const out: { framework: Framework; control: string; description: string }[] = [];
  for (const m of MAPPINGS) {
    if (keys.includes(m.match)) out.push(...m.controls);
  }
  return out;
}

export function buildReport(framework: Framework, findings: Finding[]): ComplianceReport {
  const buckets = new Map<string, { description: string; findings: Finding[] }>();
  for (const f of findings) {
    const ctls = controlsFor(f).filter((c) => c.framework === framework);
    for (const c of ctls) {
      const b = buckets.get(c.control) ?? { description: c.description, findings: [] };
      b.findings.push(f);
      buckets.set(c.control, b);
    }
  }
  const controls = Array.from(buckets.entries()).map(([control, b]) => ({
    control,
    description: b.description,
    findings: b.findings.length,
    severityCounts: b.findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    }, {}),
    sampleFindings: b.findings.slice(0, 5).map((f) => ({ id: f.id, title: f.title, severity: f.severity })),
  })).sort((a, b) => a.control.localeCompare(b.control, undefined, { numeric: true }));

  const covered = new Set(controls.map((c) => c.control));
  const uncoveredControls = ALL_CONTROLS[framework].filter((c) => !covered.has(c));

  return { framework, controls, uncoveredControls, totalFindings: findings.length };
}

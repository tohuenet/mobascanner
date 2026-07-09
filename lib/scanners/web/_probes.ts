/**
 * Shared injection probes — single source of truth for the payload set that
 * both form-fuzzer (parameters in form inputs) and query-fuzzer (parameters
 * in URL query strings) use. Keeping them here avoids drift in detection
 * heuristics between the two scanners.
 */

const SQL_ERROR_RE = /you have an error in your sql syntax|warning:\s*mysql_|unclosed quotation mark|quoted string not properly terminated|pg_query|ORA-\d{5}|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|syntax error at or near/i;
const LFI_MARKERS = ["root:x:0:0:", "[boot loader]"];
const CMD_MARKERS = [/uid=\d+\(.+?\)\s+gid=\d+/, /\bDarwin\b.*?Kernel Version/];

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ProbeHit {
  reason: string;
  severity: Severity;
  cwe: string[];
  owasp: string[];
  remediation: string;
}

export interface Probe {
  rule: string;
  payload: string;
  detect: (
    resp: { body: string; latencyMs: number; contentType: string },
    canary: string,
  ) => ProbeHit | null;
}

function looksLikeHtml(ct: string): boolean {
  return /\b(text\/html|application\/xhtml)\b/i.test(ct);
}
function looksLikeJson(ct: string): boolean {
  return /\b(application\/json|application\/.*\+json)\b/i.test(ct);
}

/** Build the probe list for a given canary. Each probe is one payload + one
 *  detection rule. Detection runs against the response body / content-type /
 *  latency — keep it cheap so we can iterate over many params quickly. */
export function buildProbes(canary: string): Probe[] {
  return [
    {
      rule: "xss/reflected",
      payload: `"<svg/onload=alert('${canary}')>`,
      detect: (r) => {
        if (!r.body.includes(canary)) return null;
        if (looksLikeJson(r.contentType) && !looksLikeHtml(r.contentType)) {
          return {
            reason: "parameter is echoed in JSON response (input-reflection, NOT browser-executable XSS)",
            severity: "info",
            cwe: ["CWE-200"],
            owasp: ["A05:2021"],
            remediation:
              "Confirm the response Content-Type is json and not rendered as HTML anywhere downstream.",
          };
        }
        if (!looksLikeHtml(r.contentType)) return null;
        if (r.body.includes("&lt;svg") || r.body.includes("&quot;&lt;svg")) return null;
        const tagRe = new RegExp(`<svg[^>]*${canary}`, "i");
        if (!tagRe.test(r.body)) return null;
        return {
          reason: `payload reflected as a live HTML tag (canary "${canary}")`,
          severity: "high",
          cwe: ["CWE-79"],
          owasp: ["A03:2021"],
          remediation:
            "Encode untrusted input in the appropriate HTML context. Apply CSP.",
        };
      },
    },
    {
      rule: "sqli/error",
      payload: "'\"`)/*--",
      detect: (r) =>
        SQL_ERROR_RE.test(r.body)
          ? {
              reason: "DB engine error string in response",
              severity: "critical",
              cwe: ["CWE-89"],
              owasp: ["A03:2021"],
              remediation: "Use parameterized queries / prepared statements.",
            }
          : null,
    },
    {
      rule: "sqli/time",
      payload: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
      detect: (r) =>
        r.latencyMs >= 4500
          ? {
              reason: `response delayed ${Math.round(r.latencyMs)}ms after sleep payload`,
              severity: "critical",
              cwe: ["CWE-89"],
              owasp: ["A03:2021"],
              remediation: "Use parameterized queries / prepared statements.",
            }
          : null,
    },
    {
      rule: "lfi/traversal",
      payload: "../../../../etc/passwd",
      detect: (r) =>
        LFI_MARKERS.some((m) => r.body.includes(m))
          ? {
              reason: "system file content disclosed in response",
              severity: "critical",
              cwe: ["CWE-22"],
              owasp: ["A01:2021"],
              remediation:
                "Reject paths containing `..`, normalize via realpath, allow-list filenames.",
            }
          : null,
    },
    {
      rule: "cmdi/exec",
      payload: ";id; #",
      detect: (r) =>
        CMD_MARKERS.some((m) => m.test(r.body))
          ? {
              reason: "shell command output in response",
              severity: "critical",
              cwe: ["CWE-78"],
              owasp: ["A03:2021"],
              remediation:
                "Never pass user input to shells; use language-native argv APIs.",
            }
          : null,
    },
  ];
}

/** Effective rule for emission — the JSON-echo case rewrites a high-severity
 *  rule to an info-level reflection note so triage doesn't drown in noise. */
export function effectiveRule(probeRule: string, hit: ProbeHit): string {
  if (hit.severity === "info" && /reflection|echo/i.test(hit.reason)) {
    return "reflection/json-echo";
  }
  return probeRule;
}

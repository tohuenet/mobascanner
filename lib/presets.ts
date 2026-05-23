/**
 * Scanner presets — opinionated bundles for common engagement modes.
 *
 * Each preset is `{ enabled: string[]; options: ... }` ready to drop into
 * the POST /api/scans body.
 *
 *   - `quick`        : 5-min posture check; passive only, no active payloads.
 *   - `bug-bounty`   : non-destructive active scans suitable for in-scope
 *                       hunts where you must NOT degrade service.
 *   - `pentest-full` : everything we have, including aggressive probes.
 *                       Only run on systems you fully control.
 *   - `compliance`   : scanners that map to PCI-DSS / SOC 2 / HIPAA controls.
 */

export interface Preset {
  name: string;
  description: string;
  enabled: string[];
  options?: Record<string, Record<string, unknown>>;
}

export const PRESETS: Record<string, Preset> = {
  quick: {
    name: "Quick posture check",
    description: "5-minute passive scan: headers, cookies, TLS, fingerprint, content-discovery, SRI, email auth, HSTS preload.",
    enabled: [
      "web.crawler", "web.headers", "web.cookies", "web.tls", "web.cors",
      "web.fingerprint", "web.content-discovery", "web.sri", "web.email-auth",
      "web.hsts-preload", "web.api-key-in-url", "web.cve-pack", "web.deserialization",
    ],
  },
  "bug-bounty": {
    name: "Bug-bounty (non-destructive)",
    description: "Active scans suitable for in-scope third-party programs — no race-conditions, no brute-force, no file-upload abuse.",
    enabled: [
      "web.crawler", "web.headers", "web.cookies", "web.tls", "web.cors",
      "web.fingerprint", "web.content-discovery", "web.sri", "web.email-auth",
      "web.api-key-in-url", "web.deserialization",
      "web.active-injection", "web.sqli", "web.ssti", "web.nosql", "web.xxe",
      "web.proto-pollution", "web.idor", "web.verb-tampering", "web.jwt",
      "web.jwt-crack", "web.cve-pack", "web.graphql-fuzzer", "web.source-map",
      "web.stack-trace", "web.subdomain-enum", "web.dns-audit", "web.aws-bucket",
      "web.custom-rules",
    ],
    options: {
      "web.crawler": { maxPages: 50, maxDepth: 3 },
    },
  },
  "pentest-full": {
    name: "Full pentest",
    description: "Every scanner enabled. Aggressive — only run on systems you own / have written authorization to test.",
    enabled: [
      "web.crawler", "web.headers", "web.cookies", "web.tls", "web.crawler", "web.ports",
      "web.cors", "web.jwt", "web.fingerprint", "web.content-discovery",
      "web.active-injection", "web.subdomain-enum", "web.form-fuzzer", "web.brute-login",
      "web.verb-tampering", "web.idor", "web.param-miner", "web.ssti", "web.nosql",
      "web.xxe", "web.proto-pollution", "web.crlf-host", "web.http-smuggling",
      "web.mass-assignment", "web.race-condition", "web.sri", "web.sqli", "web.cve-pack",
      "web.waf", "web.source-map", "web.hpp", "web.cache-poison", "web.email-auth",
      "web.cloud-meta", "web.user-enum", "web.deserialization", "web.jwt-crack",
      "web.session-fixation", "web.logout-invalidation", "web.oauth-redirect",
      "web.ldap-injection", "web.xpath-injection", "web.ssi-injection", "web.jsonp",
      "web.file-upload", "web.zip-slip", "web.range-leak", "web.graphql-fuzzer",
      "web.privesc", "web.jwt-tamper", "web.replay", "web.api-key-in-url",
      "web.dns-audit", "web.hsts-preload", "web.aws-bucket", "web.cache-deception",
      "web.backup-files", "web.stack-trace", "web.websocket", "web.stored-xss",
      "web.numeric-bounds", "web.custom-rules", "web.oob-interactsh",
    ],
    options: {
      "web.crawler": { maxPages: 100, maxDepth: 4 },
    },
  },
  compliance: {
    name: "Compliance audit",
    description: "Coverage focused on findings that map to PCI-DSS / SOC 2 / HIPAA / ISO 27001 controls.",
    enabled: [
      "web.crawler", "web.headers", "web.cookies", "web.tls", "web.cors", "web.jwt",
      "web.content-discovery", "web.email-auth", "web.hsts-preload", "web.dns-audit",
      "web.api-key-in-url", "web.fingerprint", "web.cve-pack", "web.deserialization",
      "web.source-map", "web.sri", "web.aws-bucket", "web.custom-rules",
    ],
  },
};

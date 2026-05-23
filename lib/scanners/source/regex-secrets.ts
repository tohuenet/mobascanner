/**
 * Regex-based secret scanner — built-in fallback for when gitleaks/trufflehog
 * aren't installed. Patterns adapted from the public gitleaks default ruleset
 * (MIT licensed) — only the highest-precision rules are kept here so the
 * false-positive rate stays low.
 *
 * Reference: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { draft, type Scanner } from "../../engine/scanner";
import { truncate, walkFiles } from "../common";
import { resolveSourceTarget } from "./git-import";

interface SecretRule {
  id: string;
  description: string;
  re: RegExp;
  severity: "critical" | "high" | "medium";
}

const RULES: SecretRule[] = [
  { id: "aws-access-key",       description: "AWS Access Key ID",        re: /\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b/g, severity: "critical" },
  { id: "aws-secret-key",       description: "AWS Secret Access Key",    re: /\baws(.{0,20})?(?:secret|access)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]/g, severity: "critical" },
  { id: "github-pat",           description: "GitHub Personal Access Token", re: /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g, severity: "critical" },
  { id: "github-fine-grained",  description: "GitHub fine-grained PAT",   re: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g, severity: "critical" },
  { id: "slack-token",          description: "Slack Token",               re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: "high" },
  { id: "stripe-key",           description: "Stripe API Key",            re: /\bsk_(live|test)_[0-9a-zA-Z]{24,}\b/g, severity: "critical" },
  { id: "google-api-key",       description: "Google API Key",            re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "high" },
  { id: "openai-key",           description: "OpenAI API Key",            re: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/g, severity: "critical" },
  { id: "anthropic-key",        description: "Anthropic API Key",         re: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b/g, severity: "critical" },
  { id: "jwt",                  description: "JSON Web Token",            re: /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: "medium" },
  { id: "private-key-pem",      description: "Private key (PEM)",         re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g, severity: "critical" },
  { id: "npm-token",            description: "NPM Auth Token",            re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "high" },
  { id: "generic-password-url", description: "Password in URL",           re: /\b[a-z][a-z0-9+\-.]+:\/\/[^\s:@/]+:[^\s:@/]+@[A-Za-z0-9._-]+/g, severity: "high" },
];

const SCAN_EXTS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".rb", ".php", ".java", ".go", ".rs", ".cs", ".kt", ".swift",
  ".env", ".envrc", ".sh", ".bash", ".zsh", ".fish",
  ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
  ".json", ".xml", ".properties", ".tf", ".tfvars", ".hcl",
  ".md", ".txt", ".sql",
]);

const SKIP_FILES = /\.(min\.js|map|lock|svg|png|jpg|jpeg|gif|ico|woff2?|ttf|eot)$/i;

export const regexSecretsScanner: Scanner = {
  id: "source.regex-secrets",
  name: "Secret Patterns",
  kind: "source",
  description: "High-precision regex sweep for AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, and other common secret patterns.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "source.regex-secrets",
      name: "Secret Patterns",
      kind: "source",
      backend: "builtin",
      status: "available",
      description: "Built-in regex-based secret scanner (rules adapted from gitleaks defaults).",
      upstream: "https://github.com/gitleaks/gitleaks",
      license: "MIT",
    };
  },

  async run(ctx) {
    const root = await resolveSourceTarget(ctx.scanId, ctx.target, ctx.log);
    await ctx.log("info", `scanning ${root}`);

    let scanned = 0;
    const maxFiles = Math.min(Number(ctx.options.maxFiles) || 5000, 50000);

    for await (const file of walkFiles(root, { maxFiles })) {
      if (ctx.signal.aborted) break;
      const ext = path.extname(file).toLowerCase();
      if (SKIP_FILES.test(file)) continue;
      if (ext && !SCAN_EXTS.has(ext)) continue;

      let content: string;
      try { content = await fs.readFile(file, "utf8"); }
      catch { continue; }
      // Skip large + binary-looking files
      if (content.length > 1024 * 1024) continue;
      if (content.indexOf(String.fromCharCode(0)) !== -1) continue;

      for (const rule of RULES) {
        rule.re.lastIndex = 0;
        for (const m of content.matchAll(rule.re)) {
          const before = content.slice(0, m.index ?? 0);
          const line = before.split("\n").length;
          const col = (m.index ?? 0) - before.lastIndexOf("\n");

          await ctx.emit(draft({
            severity: rule.severity,
            confidence: rule.severity === "critical" ? "high" : "medium",
            title: `${rule.description} found in ${path.relative(root, file)}`,
            description: `A pattern matching "${rule.description}" was detected. Hard-coded secrets must be rotated immediately and moved to a secrets manager.`,
            ruleId: `secret/${rule.id}`,
            cwe: ["CWE-798"],
            owasp: ["A07:2021"],
            location: {
              file: path.relative(root, file).replace(/\\/g, "/"),
              line,
              column: Math.max(1, col),
              snippet: truncate(m[0], 120),
            },
            evidence: { match: truncate(m[0], 200) },
            remediation: "Rotate the credential, remove it from git history (e.g. `git filter-repo`), and load it via env vars or a secrets manager.",
            references: ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
          }));
        }
      }

      scanned += 1;
      if (scanned % 250 === 0) {
        await ctx.progress(Math.min(scanned / maxFiles, 0.95), `${scanned} files`);
      }
    }
    await ctx.progress(1, `${scanned} files scanned`);
  },
};

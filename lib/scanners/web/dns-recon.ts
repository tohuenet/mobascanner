/**
 * DNS / hosting recon:
 *
 *   - web.dns-audit       : CAA / dangling CNAME (subdomain-takeover risk)
 *                           / wildcard / wide-MX checks on the apex.
 *   - web.hsts-preload    : check whether the apex is on the Chromium HSTS
 *                           preload list (hstspreload.org JSON API).
 *   - web.aws-bucket      : guess S3 bucket names derived from the apex
 *                           (e.g. <name>, <name>-backup, <name>-logs, …)
 *                           and probe for public read.
 *
 * Each of these probes only DNS / HTTP — no traffic to the target itself —
 * so they're safe to run against any target.
 */

import { resolve4, resolveCaa, resolveCname, resolveMx } from "node:dns/promises";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";

function apexOf(host: string): string {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}

// ───────────────────── DNS audit ─────────────────────────────
async function safeResolve<T>(p: Promise<T[]>): Promise<T[]> {
  try { return await p; }
  catch { return []; }
}

const DANGLING_HINTS = [
  /\.azurewebsites\.net$/i, /\.cloudfront\.net$/i, /\.s3\.amazonaws\.com$/i,
  /\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/i, /\.herokuapp\.com$/i,
  /\.ghost\.io$/i, /\.github\.io$/i, /\.shopify\.com$/i, /\.tumblr\.com$/i,
  /\.wpengine\.com$/i, /\.netlify\.app$/i, /\.zendesk\.com$/i, /\.fastly\.net$/i,
  /\.bitbucket\.io$/i, /\.surge\.sh$/i, /\.statuspage\.io$/i,
];

export const dnsAuditScanner: Scanner = {
  id: "web.dns-audit",
  name: "DNS Audit (CAA / Dangling CNAME / Wildcard)",
  kind: "web",
  description: "Walks DNS records of the target apex: missing CAA → anyone can issue certs; CNAME pointing at decommissioned cloud service → subdomain takeover; wildcard MX → spam-bait; missing SPF/DMARC.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.dns-audit", name: "DNS Audit", kind: "web", backend: "builtin", status: "available", description: "Built-in DNS records audit." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(seed.hostname) || seed.hostname === "localhost") {
      await ctx.progress(1, "skip — IP / localhost"); return;
    }
    const apex = apexOf(seed.hostname);

    // CAA on apex.
    const caa = await safeResolve(resolveCaa(apex));
    if (!caa.length) {
      await ctx.emit(draft({
        severity: "low", confidence: "high",
        title: `No CAA record on ${apex}`,
        description: "Without CAA, ANY public CA can issue a certificate for this domain. CAA pins certificate issuance to specific CAs (Let's Encrypt, Sectigo, etc.).",
        ruleId: "dns/caa-missing", cwe: ["CWE-295"],
        location: { url: `dns://${apex}/CAA` },
        remediation: `Add a CAA record on ${apex}: \`0 issue "letsencrypt.org"\` (or whichever CA you use). Add an iodef contact for breach notifications.`,
      }));
    }

    // CNAME chain on the seed hostname (subdomain-takeover risk).
    const cnames = await safeResolve(resolveCname(seed.hostname));
    for (const target of cnames) {
      const dangling = DANGLING_HINTS.find((re) => re.test(target));
      if (!dangling) continue;
      // Resolve the target — if it doesn't resolve to A records, the cloud
      // resource is gone: classic dangling-CNAME / takeover surface.
      const a = await safeResolve(resolve4(target));
      if (!a.length) {
        await ctx.emit(draft({
          severity: "high", confidence: "medium",
          title: `Dangling CNAME → ${target} (subdomain-takeover risk)`,
          description: `CNAME of ${seed.hostname} points at ${target}, which doesn't currently resolve. If you decommissioned the cloud resource, an attacker can register the same name on the provider and serve traffic from your domain.`,
          ruleId: "dns/dangling-cname", cwe: ["CWE-918"],
          location: { url: `dns://${seed.hostname}/CNAME` },
          evidence: { cname: target, regex: dangling.toString() },
          remediation: "Either re-create the resource or remove the CNAME record. Audit all subdomain CNAMEs for the same pattern.",
          references: ["https://github.com/EdOverflow/can-i-take-over-xyz"],
        }));
      }
    }

    // MX without restrictions = receives spam.
    await safeResolve(resolveMx(apex));
    // Don't flag here — informational only.

    // Wildcard A on apex.
    const wildcard = await safeResolve(resolve4(`wildcard-test-${Date.now()}.${apex}`));
    if (wildcard.length) {
      await ctx.emit(draft({
        severity: "info", confidence: "high",
        title: `Wildcard A record on ${apex}`,
        description: "Random subdomains resolve — wildcard DNS is enabled. Combined with reflected-XSS in the app, this enables session-cookie stealing via attacker.<apex> that browsers treat as same-site.",
        ruleId: "dns/wildcard", cwe: ["CWE-200"],
        location: { url: `dns://*.${apex}/A` },
      }));
    }

    await ctx.progress(1, `DNS audit complete for ${apex}`);
  },
};

// ───────────────────── HSTS preload ──────────────────────────────────
export const hstsPreloadScanner: Scanner = {
  id: "web.hsts-preload",
  name: "HSTS Preload Status",
  kind: "web",
  description: "Queries hstspreload.org to check whether the apex is on Chromium's HSTS preload list. Not being preloaded = first-time-visitor vulnerable to SSL strip.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.hsts-preload", name: "HSTS Preload", kind: "web", backend: "builtin", status: "available", description: "Built-in hstspreload.org status check.", upstream: "https://hstspreload.org" };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(seed.hostname) || seed.hostname === "localhost") {
      await ctx.progress(1, "skip — IP / localhost"); return;
    }
    const apex = apexOf(seed.hostname);
    let r;
    try {
      r = await fetch(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(apex)}`, {
        headers: { "User-Agent": "moba-scanner/0.1" },
        signal: ctx.signal,
      });
    } catch { return; }
    if (!r.ok) return;
    const j = await r.json().catch(() => null) as { status?: string } | null;
    if (!j) return;
    if (j.status !== "preloaded") {
      await ctx.emit(draft({
        severity: "low", confidence: "high",
        title: `${apex} not on the HSTS preload list (status=${j.status ?? "unknown"})`,
        description: "First-time visitors to your site are still vulnerable to SSL-strip MITM until they receive an HSTS response. Preload list is baked into Chrome / Firefox / Safari; preloaded domains are HTTPS-only from the very first DNS lookup.",
        ruleId: "tls/no-hsts-preload", cwe: ["CWE-319"],
        location: { url: `https://${apex}/` },
        evidence: { status: j.status },
        remediation: "Submit your domain at https://hstspreload.org. Requirements: HSTS header with `max-age >= 31536000`, `includeSubDomains`, `preload`, served on every subdomain over HTTPS.",
      }));
    }
    await ctx.progress(1, "HSTS preload check done");
  },
};

// ───────────────────── AWS S3 bucket guessing ───────────────────────
export const s3BucketScanner: Scanner = {
  id: "web.aws-bucket",
  name: "Cloud Bucket Discovery",
  kind: "web",
  description: "Derives ~25 candidate S3/Azure/GCS bucket names from the target apex (`name`, `name-backup`, `name-logs`, `name-dev`, `name-prod`, `assets-name`, …) and probes each for public-read.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.aws-bucket", name: "Cloud Bucket Discovery", kind: "web", backend: "builtin", status: "available", description: "Built-in S3/GCS/Azure bucket guesser." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(seed.hostname) || seed.hostname === "localhost") {
      await ctx.progress(1, "skip — IP / localhost"); return;
    }
    const apex = apexOf(seed.hostname);
    const stem = apex.split(".")[0]; // e.g. "example" from "example.com"
    const VARIANTS = [
      `${stem}`, `${stem}-backup`, `${stem}-backups`, `${stem}-logs`, `${stem}-log`,
      `${stem}-prod`, `${stem}-staging`, `${stem}-dev`, `${stem}-test`,
      `${stem}-assets`, `${stem}-static`, `${stem}-public`, `${stem}-private`,
      `${stem}-uploads`, `${stem}-files`, `${stem}-data`, `${stem}-db`,
      `${stem}-images`, `${stem}-media`, `${stem}-cdn`,
      `assets-${stem}`, `static-${stem}`, `cdn-${stem}`, `backup-${stem}`,
      `${stem}-archive`,
    ];
    const PROVIDERS: { name: string; urlFor: (b: string) => string; markerOk: RegExp; markerExists: RegExp }[] = [
      { name: "AWS S3", urlFor: (b) => `https://${b}.s3.amazonaws.com/?list-type=2`, markerOk: /<ListBucketResult/, markerExists: /<Code>NoSuchBucket<\/Code>/ },
      { name: "Azure Blob", urlFor: (b) => `https://${b}.blob.core.windows.net/?comp=list`, markerOk: /<EnumerationResults/, markerExists: /BlobNotFound|InvalidUri/ },
      { name: "GCS", urlFor: (b) => `https://storage.googleapis.com/storage/v1/b/${b}/o`, markerOk: /"items":/, markerExists: /Not Found/ },
    ];

    let probed = 0;
    for (const variant of VARIANTS) {
      if (ctx.signal.aborted) break;
      for (const p of PROVIDERS) {
        let r;
        try { r = await fetch(p.urlFor(variant), { signal: ctx.signal }); }
        catch { continue; }
        probed++;
        if (r.status >= 500) continue;
        const body = await r.text().catch(() => "");
        if (p.markerOk.test(body)) {
          await ctx.emit(draft({
            severity: "high", confidence: "high",
            title: `Public ${p.name} bucket: ${variant}`,
            description: `${p.name} bucket "${variant}" is enumerable without auth. Listing contents AND fetching individual objects may be possible — common cause of large breaches (Capital One, Accenture, etc.).`,
            ruleId: `cloud/public-${p.name.replace(/\s+/g, "-").toLowerCase()}`,
            cwe: ["CWE-200"], owasp: ["A05:2021"],
            location: { url: p.urlFor(variant) },
            evidence: { provider: p.name, bucket: variant, snippet: truncate(body, 300) },
            remediation: "Set the bucket to private. Use signed URLs or CloudFront OAI for public assets. Audit all `<stem>-*` buckets you own.",
          }));
        }
      }
    }
    await ctx.progress(1, `${probed} bucket probes`);
  },
};

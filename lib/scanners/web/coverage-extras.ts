/**
 * Coverage extras — fills meaningful gaps from the audit:
 *
 *   - web.waf            : WAF / CDN fingerprint via response headers + canary probe
 *   - web.source-map     : `*.js.map` exposure on every JS asset the crawler saw
 *   - web.hpp            : HTTP Parameter Pollution — duplicate param, observe diff
 *   - web.cache-poison   : Web cache poisoning via X-Forwarded-Host / X-Original-URL
 *                          / X-Forwarded-Scheme / X-Original-Host (header reflected
 *                          into a cacheable response)
 *   - web.email-auth     : DNS lookups for SPF / DMARC / DKIM (apex + common selectors)
 *   - web.cloud-meta     : Azure / GCP / IMDSv2 metadata probes (extends SSRF)
 *   - web.user-enum      : Username enumeration via login response timing/content
 *   - web.deserialization: Java / PHP / Python / .NET / Ruby serialization markers
 */

import { promises as dns } from "node:dns";
import { randomBytes } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

// ─────────────────────────── WAF detection ─────────────────────────────
interface WafSig {
  name: string;
  headerHints?: { name: string; re?: RegExp }[];
  cookieHints?: RegExp;
  bodyHints?: RegExp;
}
const WAF_SIGS: WafSig[] = [
  { name: "Cloudflare",  headerHints: [{ name: "cf-ray" }, { name: "server", re: /cloudflare/i }] },
  { name: "Akamai",      headerHints: [{ name: "x-akamai-edgescape" }, { name: "akamai-grn" }, { name: "server", re: /akamaighost/i }] },
  { name: "Imperva (Incapsula)", cookieHints: /incap_ses|visid_incap/i, headerHints: [{ name: "x-iinfo" }, { name: "x-cdn", re: /incapsula/i }] },
  { name: "AWS WAF / CloudFront", headerHints: [{ name: "x-amzn-requestid" }, { name: "x-amz-cf-id" }, { name: "x-amz-cf-pop" }, { name: "x-amzn-trace-id" }] },
  { name: "Sucuri",      headerHints: [{ name: "server", re: /sucuri/i }, { name: "x-sucuri-id" }] },
  { name: "F5 BIG-IP ASM", cookieHints: /TS\w{6,}=|BIGipServer/i, headerHints: [{ name: "x-frame-options", re: /deny.*?BIGip/i }] },
  { name: "Barracuda",   headerHints: [{ name: "barracuda-ad-cookie" }] },
  { name: "Fastly",      headerHints: [{ name: "x-served-by", re: /fastly/i }, { name: "x-cache", re: /fastly/i }] },
  { name: "ModSecurity", headerHints: [{ name: "server", re: /mod_security|modsecurity/i }] },
  { name: "Wallarm",     headerHints: [{ name: "x-wallarm" }] },
  { name: "Wordfence",   bodyHints: /wordfence/i },
  { name: "Azure Front Door", headerHints: [{ name: "x-azure-ref" }] },
];

export const wafScanner: Scanner = {
  id: "web.waf",
  name: "WAF / CDN Fingerprint",
  kind: "web",
  description: "Identifies Cloudflare / Akamai / Imperva / AWS WAF / Sucuri / F5 / Barracuda / Fastly / ModSecurity / Wallarm / Wordfence / Azure Front Door from response headers + cookies + canary probe.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.waf", name: "WAF Fingerprint", kind: "web", backend: "builtin", status: "available", description: "Built-in WAF / CDN fingerprinter." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    let r;
    try { r = await session.fetch(seed.toString(), { signal: ctx.signal }); } catch { return; }

    const detected = new Set<string>();
    for (const sig of WAF_SIGS) {
      if (sig.headerHints) for (const h of sig.headerHints) {
        const v = r.res.headers.get(h.name);
        if (v && (h.re ? h.re.test(v) : true)) { detected.add(sig.name); break; }
      }
      if (sig.cookieHints && sig.cookieHints.test(r.res.headers.get("set-cookie") ?? "")) detected.add(sig.name);
      if (sig.bodyHints && sig.bodyHints.test(r.body)) detected.add(sig.name);
    }
    // Canary probe: send an obvious attack-string in the URL — many WAFs
    // respond with their own block page (status 403/406/501 + branded text).
    const probeUrl = new URL(seed.toString());
    probeUrl.searchParams.set("xss-canary", "<script>alert(1)</script>");
    let pr;
    try { pr = await session.fetch(probeUrl.toString(), { signal: ctx.signal }); } catch { /* tolerate */ }
    if (pr) {
      if (pr.res.status === 403 || pr.res.status === 406 || pr.res.status === 501) {
        const body = pr.body.toLowerCase();
        if (/cloudflare|attention required/.test(body)) detected.add("Cloudflare");
        if (/access denied.*?akamai|reference\s*#\d+/.test(body)) detected.add("Akamai");
        if (/incapsula|imperva/.test(body)) detected.add("Imperva (Incapsula)");
        if (/aws.*?(\bwaf\b|access denied)/.test(body)) detected.add("AWS WAF / CloudFront");
        if (/sucuri.*?firewall/.test(body)) detected.add("Sucuri");
        if (/the request.*?could not be processed/.test(body)) detected.add("Barracuda");
        if (/wallarm/.test(body)) detected.add("Wallarm");
        // Generic 403 from canary = SOMETHING is filtering even if we don't know what.
        if (!detected.size) detected.add("(generic WAF blocking attack-string)");
      }
    }
    if (detected.size) {
      await ctx.emit(draft({
        severity: "info", confidence: "medium",
        title: `WAF / CDN detected: ${[...detected].join(", ")}`,
        description: "Knowing the WAF guides bypass strategy (e.g. Cloudflare blocks payloads in body but not in cookies; Akamai is sensitive to `Connection: close`).",
        ruleId: "waf/detected",
        location: { url: seed.toString() },
        evidence: { detected: [...detected], canaryStatus: pr?.res.status, headers: Object.fromEntries(r.res.headers) },
      }));
    }
    await ctx.progress(1, `${detected.size} WAF/CDN signature(s) matched`);
  },
};

// ─────────────────────────── Source map exposure ────────────────────────
export const sourceMapScanner: Scanner = {
  id: "web.source-map",
  name: "Source Map Exposure",
  kind: "web",
  description: "For every `<script src=...>` the crawler saw, GETs `<src>.map` and flags reachable source maps. Source maps re-create unminified source + comments — devastating for closed-source apps.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.source-map", name: "Source Map", kind: "web", backend: "builtin", status: "available", description: "Built-in source-map exposure scanner." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const tried = new Set<string>();
    let probed = 0; let exposed = 0;
    // Pull every asset URL from sitemap pages by re-extracting <script src>.
    for (const p of map.pages) {
      if (ctx.signal.aborted) break;
      if (!(p.contentType ?? "").includes("html")) continue;
      let html;
      try { html = (await session.fetch(p.url, { signal: ctx.signal })).body; } catch { continue; }
      for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+\.js)(?:\?[^"']*)?["']/gi)) {
        const src = m[1]; let abs;
        try { abs = new URL(src, p.url).toString(); } catch { continue; }
        const mapUrl = abs + ".map";
        if (tried.has(mapUrl)) continue;
        tried.add(mapUrl);
        let r;
        try { r = await session.fetch(mapUrl, { signal: ctx.signal }); } catch { continue; }
        probed++;
        if (r.res.status === 200 && (r.body.includes('"sources"') || r.body.includes('"version":3'))) {
          exposed++;
          await ctx.emit(draft({
            severity: "medium", confidence: "high",
            title: `Source map exposed: ${mapUrl}`,
            description: "Source map served publicly — attackers can recover full TypeScript/JSX source, comments, file paths, and unobfuscated business logic.",
            ruleId: "source-map/exposed",
            cwe: ["CWE-540"], owasp: ["A05:2021"],
            location: { url: mapUrl },
            evidence: { snippet: truncate(r.body, 300) },
            remediation: "Stop publishing source maps to production. If needed for monitoring, gate behind auth or upload to Sentry/Datadog only.",
          }));
        }
      }
    }
    await ctx.progress(1, `${probed} maps probed, ${exposed} exposed`);
  },
};

// ─────────────────────── HTTP Parameter Pollution ───────────────────────
export const hppScanner: Scanner = {
  id: "web.hpp",
  name: "HTTP Parameter Pollution",
  kind: "web",
  description: "Sends the same query parameter twice with different values; flags endpoints whose response differs from baseline (server merges duplicates, picks one, reflects both). Often defeats input validation that runs once.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.hpp", name: "HPP", kind: "web", backend: "builtin", status: "available", description: "Built-in HTTP Parameter Pollution probe." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const targets = (map?.pages ?? []).filter((p) => {
      try { return [...new URL(p.url).searchParams.keys()].length > 0; } catch { return false; }
    });
    if (!targets.length && [...seed.searchParams.keys()].length) targets.push({ url: seed.toString(), status: 200, method: "GET" } as never);

    const canary = "moba" + randomBytes(3).toString("hex");
    let done = 0;
    for (const p of targets.slice(0, 20)) {
      if (ctx.signal.aborted) break;
      const u = safeUrl(p.url); if (!u) continue;
      for (const param of u.searchParams.keys()) {
        // Single value baseline.
        let baselineUrl = new URL(u.toString());
        baselineUrl.searchParams.set(param, "ok");
        let baseline;
        try { baseline = await session.fetch(baselineUrl.toString(), { signal: ctx.signal }); } catch { continue; }
        // Polluted: same key twice.
        const pollutedUrl = baselineUrl.toString() + `&${param}=${canary}`;
        let r;
        try { r = await session.fetch(pollutedUrl, { signal: ctx.signal }); } catch { continue; }
        done++;
        const lenDelta = Math.abs(r.body.length - baseline.body.length);
        const canaryReflected = r.body.includes(canary);
        if (canaryReflected || lenDelta > Math.max(64, baseline.body.length * 0.05)) {
          await ctx.emit(draft({
            severity: canaryReflected ? "medium" : "low",
            confidence: canaryReflected ? "high" : "medium",
            title: `HTTP Parameter Pollution on "${param}" of ${u.pathname}`,
            description: `Duplicating parameter \`${param}\` changed the response${canaryReflected ? " AND the second value was reflected — input validation likely runs against the first value while the app reads the second" : ""}.`,
            ruleId: "hpp/duplicate-param",
            cwe: ["CWE-235"], owasp: ["A03:2021"],
            location: { url: pollutedUrl, snippet: param },
            evidence: { baselineLen: baseline.body.length, pollutedLen: r.body.length, canaryReflected, lenDelta },
            remediation: "Reject duplicate parameters at the framework layer, or canonicalize before validation. Don't rely on `$_GET[param]` returning a string when both single and array forms are possible.",
          }));
        }
      }
    }
    await ctx.progress(1, `${done} HPP probes`);
  },
};

// ─────────────────────────── Cache poisoning ───────────────────────────
export const cachePoisonScanner: Scanner = {
  id: "web.cache-poison",
  name: "Web Cache Poisoning",
  kind: "web",
  description: "Sends unkeyed headers (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, X-Forwarded-Scheme, X-Forwarded-Port) and checks whether they're reflected into a cacheable response. Reflection + Cache-Control: public = poisoning surface.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.cache-poison", name: "Cache Poisoning", kind: "web", backend: "builtin", status: "available", description: "Built-in unkeyed-header cache-poison probe." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Port", "X-Original-URL", "X-Rewrite-URL", "X-Host", "X-Forwarded-Server"];
    const canary = `mobapoison${randomBytes(3).toString("hex")}.example`;
    const targets = new Set<string>([seed.toString()]);
    for (const p of (map?.pages ?? []).slice(0, 20)) targets.add(p.url);

    let probed = 0; let hits = 0;
    for (const url of targets) {
      if (ctx.signal.aborted) break;
      for (const h of HEADERS) {
        let r;
        try { r = await session.fetch(url, { headers: { [h]: canary }, signal: ctx.signal }); } catch { continue; }
        probed++;
        const cacheable = /public|s-maxage|max-age=\d/.test(r.res.headers.get("cache-control") ?? "") ||
          /HIT|cached/i.test(r.res.headers.get("x-cache") ?? "") ||
          !!r.res.headers.get("age");
        const reflected = r.body.includes(canary) ||
          (r.res.headers.get("location") ?? "").includes(canary) ||
          (r.res.headers.get("link") ?? "").includes(canary);
        if (reflected) {
          hits++;
          await ctx.emit(draft({
            severity: cacheable ? "high" : "medium", confidence: cacheable ? "high" : "low",
            title: `Cache poisoning surface: ${h} reflected${cacheable ? " on a CACHEABLE response" : ""} (${url})`,
            description: cacheable
              ? `Server reflects \`${h}: ${canary}\` AND marks the response as cacheable. Attackers can poison the shared cache so every subsequent visitor receives the attacker-controlled URL/host.`
              : `Server reflects \`${h}\`, which is dangerous if any upstream cache (CDN, varnish, nginx proxy_cache) keys responses without including this header.`,
            ruleId: "cache/unkeyed-header-reflection",
            cwe: ["CWE-444"], owasp: ["A05:2021"],
            location: { url, snippet: `${h}: <attacker>` },
            evidence: {
              header: h,
              cacheable,
              cacheControl: r.res.headers.get("cache-control"),
              age: r.res.headers.get("age"),
              xCache: r.res.headers.get("x-cache"),
            },
            remediation: "Either strip unkeyed headers at the edge, or include them in the cache key (Vary). Disable cache for any response that incorporates request headers.",
            references: ["https://portswigger.net/web-security/web-cache-poisoning"],
          }));
        }
      }
    }
    await ctx.progress(1, `${probed} probes, ${hits} reflections`);
  },
};

// ─────────────────────── Email auth (SPF / DMARC / DKIM) ─────────────────
async function txt(host: string): Promise<string[]> {
  try { return (await dns.resolveTxt(host)).map((parts) => parts.join("")); } catch { return []; }
}
function apexOf(host: string): string {
  const parts = host.split(".");
  return parts.length <= 2 ? host : parts.slice(-2).join(".");
}

export const emailAuthScanner: Scanner = {
  id: "web.email-auth",
  name: "Email Auth (SPF / DKIM / DMARC)",
  kind: "web",
  description: "DNS lookup for the target apex's SPF / DMARC records and a few common DKIM selectors. Missing / weak records enable email spoofing of @<your-domain>.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.email-auth", name: "Email Auth", kind: "web", backend: "builtin", status: "available", description: "Built-in SPF / DKIM / DMARC DNS audit." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const apex = apexOf(seed.hostname);
    if (apex === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(apex)) { await ctx.progress(1, "skip — IP / localhost"); return; }

    // SPF — TXT on apex starting with v=spf1
    const apexTxt = await txt(apex);
    const spf = apexTxt.find((t) => /^v=spf1\b/i.test(t));
    if (!spf) {
      await ctx.emit(draft({
        severity: "medium", confidence: "high",
        title: `Missing SPF record for ${apex}`,
        description: "Without SPF, anyone can send email claiming to be from your domain. Combined with missing/weak DMARC, attackers can spoof your domain in phishing.",
        ruleId: "email/spf-missing", cwe: ["CWE-290"],
        location: { url: `dns://${apex}/TXT` },
        remediation: `Add a TXT record on ${apex}: \`v=spf1 -all\` (no senders) or \`v=spf1 include:_spf.<provider> -all\`.`,
      }));
    } else if (/[~?]all$/.test(spf)) {
      await ctx.emit(draft({
        severity: "low", confidence: "high",
        title: `Weak SPF policy for ${apex} — ends in ${/~all$/.test(spf) ? "~all (softfail)" : "?all (neutral)"}`,
        description: "SPF terminator ~all / ?all only marks unknown senders as suspicious; -all hard-fails them and is more effective at preventing spoofing.",
        ruleId: "email/spf-weak",
        location: { url: `dns://${apex}/TXT` },
        evidence: { spf },
        remediation: "Tighten SPF to end in `-all` once you've inventoried legitimate senders.",
      }));
    }

    // DMARC — TXT on _dmarc.<apex>
    const dmarcTxt = await txt(`_dmarc.${apex}`);
    const dmarc = dmarcTxt.find((t) => /^v=DMARC1\b/i.test(t));
    if (!dmarc) {
      await ctx.emit(draft({
        severity: "medium", confidence: "high",
        title: `Missing DMARC record for ${apex}`,
        description: "DMARC tells receivers what to do with email failing SPF/DKIM. Without it, mailboxes accept spoofed mail with no policy.",
        ruleId: "email/dmarc-missing", cwe: ["CWE-290"],
        location: { url: `dns://_dmarc.${apex}/TXT` },
        remediation: `Add a TXT record on _dmarc.${apex}: \`v=DMARC1; p=reject; rua=mailto:dmarc@${apex}\`.`,
      }));
    } else if (/p=none/i.test(dmarc)) {
      await ctx.emit(draft({
        severity: "low", confidence: "high",
        title: `DMARC policy is p=none for ${apex} (monitoring only)`,
        description: "DMARC p=none means mailboxes still accept spoofed mail; only reports get sent to the rua address. Move to p=quarantine then p=reject once reports look clean.",
        ruleId: "email/dmarc-monitor-only",
        location: { url: `dns://_dmarc.${apex}/TXT` },
        evidence: { dmarc },
      }));
    }

    // DKIM — try a few common selectors.
    const SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "smtpapi", "dkim"];
    let foundDkim = false;
    for (const sel of SELECTORS) {
      const t = await txt(`${sel}._domainkey.${apex}`);
      if (t.find((x) => /v=DKIM1/i.test(x))) { foundDkim = true; break; }
    }
    if (!foundDkim) {
      await ctx.emit(draft({
        severity: "info", confidence: "medium",
        title: `No DKIM keys discovered under common selectors for ${apex}`,
        description: "Probed selectors: default, google, selector1/2, k1, mail, smtpapi, dkim. The domain may use custom selectors — confirm with email provider.",
        ruleId: "email/dkim-not-found",
        location: { url: `dns://*._domainkey.${apex}/TXT` },
        remediation: "If you send mail from this domain, publish a DKIM key (your provider configures the selector).",
      }));
    }
    await ctx.progress(1, "email auth done");
  },
};

// ─────────────────────── Cloud metadata variants ─────────────────────
const META_PROBES: { name: string; url: string; marker: RegExp }[] = [
  { name: "AWS IMDSv1", url: "http://169.254.169.254/latest/meta-data/", marker: /ami-id|instance-id|iam\/security-credentials/i },
  { name: "AWS IMDSv2 (token)", url: "http://169.254.169.254/latest/api/token", marker: /AQAEA|^[A-Za-z0-9+/=]{40,}$/ },
  { name: "Azure IMDS", url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", marker: /"compute"|"network"|"vmId"/ },
  { name: "GCP metadata", url: "http://metadata.google.internal/computeMetadata/v1/", marker: /computeMetadata|service-accounts|instance/ },
  { name: "Alibaba/Aliyun", url: "http://100.100.100.200/latest/meta-data/", marker: /instance-id|ram\//i },
  { name: "DigitalOcean", url: "http://169.254.169.254/metadata/v1.json", marker: /"droplet_id"|"public_keys"/ },
  { name: "Kubernetes API", url: "https://kubernetes.default.svc/api/v1", marker: /apiVersion|kind:.*?APIVersions/ },
];

export const cloudMetaScanner: Scanner = {
  id: "web.cloud-meta",
  name: "Cloud Metadata SSRF (AWS/Azure/GCP/Alibaba/DO/K8s)",
  kind: "web",
  description: "For each parameter that looks SSRF-shaped (url, host, target, fetch, image, callback, webhook), supplies the metadata URL of every major cloud provider and watches for that provider's marker in the response.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.cloud-meta", name: "Cloud Metadata SSRF", kind: "web", backend: "builtin", status: "available", description: "Built-in multi-cloud metadata SSRF probes." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const SSRF_PARAM_HINT = /(url|host|target|fetch|image|img|src|callback|webhook|proxy|redirect|next|return|return_to|destination|dest|uri|link|file|src_url)/i;
    const targets: { url: URL; param: string }[] = [];
    if (map) {
      for (const p of map.pages) {
        const u = safeUrl(p.url); if (!u) continue;
        for (const k of u.searchParams.keys()) if (SSRF_PARAM_HINT.test(k)) targets.push({ url: u, param: k });
      }
    }
    if (!targets.length) { await ctx.progress(1, "no SSRF-shaped params"); return; }

    let done = 0;
    for (const t of targets) {
      if (ctx.signal.aborted) break;
      for (const probe of META_PROBES) {
        const u = new URL(t.url.toString());
        u.searchParams.set(t.param, probe.url);
        let r;
        try {
          r = await session.fetch(u.toString(), {
            // Some apps require Metadata-Flavor: Google for GCP IMDS; if we
            // include it, we make the probe stronger but also more conservative
            // (some apps DON'T forward arbitrary headers).
            headers: probe.name.startsWith("GCP") ? { "metadata-flavor": "Google" } : {},
            signal: ctx.signal,
          });
        } catch { continue; }
        done++;
        if (probe.marker.test(r.body)) {
          await ctx.emit(draft({
            severity: "critical", confidence: "high",
            title: `SSRF → ${probe.name} metadata leaked via parameter "${t.param}"`,
            description: `Server fetched our metadata URL and returned ${probe.name} marker — credentials / instance metadata reachable.`,
            ruleId: `ssrf/${probe.name.replace(/[^a-z0-9]/gi, "-").toLowerCase()}`,
            cwe: ["CWE-918"], owasp: ["A10:2021"],
            location: { url: u.toString(), snippet: t.param },
            evidence: { probe: probe.url, snippet: truncate(r.body, 400) },
            remediation: "Block egress to link-local / RFC1918 ranges from app servers. Validate URLs against an allow-list. Use IMDSv2 with hop-limit 1 on AWS.",
          }));
          break;
        }
      }
    }
    await ctx.progress(1, `${done} cloud-meta SSRF probes`);
  },
};

// ─────────────────────── Username enumeration ────────────────────────
export const userEnumScanner: Scanner = {
  id: "web.user-enum",
  name: "Username Enumeration",
  kind: "web",
  description: "On each login form, submits a known-invalid username and 2-3 'common' usernames (admin / administrator / test). Compares response length / status / latency — distinguishable responses leak which usernames exist.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.user-enum", name: "Username Enumeration", kind: "web", backend: "builtin", status: "available", description: "Built-in username-enumeration tester via login form." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const loginForms = map.forms.filter((f) => f.looksLikeLogin && f.method === "POST");
    if (!loginForms.length) { await ctx.progress(1, "no login forms"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    const COMMON_USERS = ["admin", "administrator", "root", "test"];
    const INVALID = "moba__user__does__not__exist__";

    for (const form of loginForms) {
      if (ctx.signal.aborted) break;
      const userField = form.inputs.find((i) => i.type !== "password" && /(user|email|login|name)/i.test(i.name))?.name;
      const passField = form.inputs.find((i) => i.type === "password")?.name;
      if (!userField || !passField) continue;

      const probe = async (user: string) => {
        const body = new URLSearchParams();
        for (const i of form.inputs) body.set(i.name, i.value || "x");
        body.set(userField, user);
        body.set(passField, "WrongPassword!" + randomBytes(2).toString("hex"));
        const t = Date.now();
        try {
          const r = await session.fetch(form.action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: ctx.signal });
          return { user, status: r.res.status, len: r.body.length, ms: Date.now() - t, sample: truncate(r.body, 80) };
        } catch { return null; }
      };

      const baseline = await probe(INVALID);
      if (!baseline) continue;
      const results: NonNullable<Awaited<ReturnType<typeof probe>>>[] = [];
      for (const u of COMMON_USERS) {
        const r = await probe(u);
        if (r) results.push(r);
      }

      const distinguishable = results.filter((r) =>
        r.status !== baseline.status ||
        Math.abs(r.len - baseline.len) > Math.max(40, baseline.len * 0.05) ||
        Math.abs(r.ms - baseline.ms) > Math.max(800, baseline.ms * 2));

      if (distinguishable.length >= 1) {
        await ctx.emit(draft({
          severity: "low", confidence: "medium",
          title: `Username enumeration on ${form.action}`,
          description: `Login responses for invalid username vs ${distinguishable.map((d) => `"${d.user}"`).join(" / ")} are distinguishable (status / length / timing). Attackers can enumerate valid accounts before brute-forcing.`,
          ruleId: "auth/user-enum",
          cwe: ["CWE-204", "CWE-203"], owasp: ["A07:2021"],
          location: { url: form.action },
          evidence: {
            invalid: { status: baseline.status, len: baseline.len, ms: baseline.ms },
            distinguishable: distinguishable.map((d) => ({ user: d.user, status: d.status, len: d.len, ms: d.ms })),
          },
          remediation: "Make the login response identical for valid and invalid usernames (same body, same status, ideally same timing).",
        }));
      }
    }
    await ctx.progress(1, "user enum done");
  },
};

// ─────────────────── Deserialization markers ─────────────────────
export const deserializationScanner: Scanner = {
  id: "web.deserialization",
  name: "Insecure Deserialization (passive markers)",
  kind: "web",
  description: "Looks for serialized-object magic bytes / signatures in cookie values, query parameters, and response bodies — Java (`AC ED 00 05`/`rO0`), PHP (`O:N:`/`a:N:`), Python pickle (`\\x80\\x04`), .NET BinaryFormatter, Ruby Marshal.",
  defaultEnabled: true,
  async tool() {
    return { id: "web.deserialization", name: "Deserialization Markers", kind: "web", backend: "builtin", status: "available", description: "Built-in passive deserialization-format detector." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    let r;
    try { r = await session.fetch(seed.toString(), { signal: ctx.signal }); } catch { return; }
    const candidates: { name: string; value: string; source: string }[] = [];
    // Cookies (from session jar after first fetch).
    for (const [k, v] of Object.entries(session.cookies())) candidates.push({ name: k, value: v, source: "cookie" });
    // Query params from sitemap.
    if (map) for (const p of map.pages) {
      try { for (const [k, v] of new URL(p.url).searchParams) candidates.push({ name: k, value: v, source: `query@${p.url}` }); } catch {}
    }
    // First-page body chunks (only when looking like base64 / hex blobs).
    candidates.push({ name: "<body>", value: r.body, source: seed.toString() });

    const RULES: { lang: string; sig: RegExp; severity: "high" | "medium" | "low" }[] = [
      { lang: "Java (serialized)", sig: /\brO0[A-Za-z0-9+/=]{6,}/, severity: "high" },           // base64-encoded `\xAC\xED\x00\x05`
      { lang: "Java (raw)",        sig: /\xAC\xED\x00\x05/, severity: "high" },
      { lang: "PHP (serialize)",   sig: /(?:^|[=&"; >])(?:O|a|s|i|d|b|N):[\d:"{};]{4,}/, severity: "high" },
      { lang: "Python (pickle)",   sig: /\x80[\x02-\x05]/, severity: "high" },
      { lang: ".NET BinaryFormatter", sig: /\bAAEAAA[A-Za-z0-9+/=]{20,}/, severity: "high" },
      { lang: "Ruby Marshal",      sig: /\x04\x08[\x00-\xff]{4,}/, severity: "medium" },
      { lang: "YAML (Ruby/Python)", sig: /^---|!ruby\/object|!!python\/object/m, severity: "medium" },
    ];

    for (const c of candidates) {
      for (const rule of RULES) {
        if (rule.sig.test(c.value)) {
          await ctx.emit(draft({
            severity: rule.severity, confidence: "medium",
            title: `${rule.lang} serialized data in ${c.source} ("${c.name}")`,
            description: `A ${rule.lang} serialized blob was observed. If the server passes this through an unsafe deserializer, it's an RCE primitive (ysoserial-style gadgets).`,
            ruleId: `deser/${rule.lang.replace(/[^a-z0-9]/gi, "-").toLowerCase()}`,
            cwe: ["CWE-502"], owasp: ["A08:2021"],
            location: { url: seed.toString(), snippet: `${c.name} (${c.source})` },
            evidence: { lang: rule.lang, sample: truncate(c.value, 200) },
            remediation: "Avoid native deserialization of attacker-controlled data. Switch to JSON / Protobuf with explicit schemas. Apply ysoserial-aware allow-lists.",
            references: ["https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization"],
          }));
          break;
        }
      }
    }
    await ctx.progress(1, "deserialization markers done");
  },
};

/**
 * Tech / CMS fingerprint + GraphQL introspection — built-in.
 *
 * Two passes:
 *   1. Headers + body sniff — populates a list of detected stacks
 *      (WordPress, Drupal, Joomla, Shopify, Magento, Next.js, Laravel,
 *       Django, Spring, Rails, Express, ASP.NET, Cloudflare, …).
 *      Findings are info-level UNLESS the version is precise enough to
 *      look up CVEs.
 *   2. Common API roots — checks /graphql, /api/graphql, /v1/graphql for
 *      introspection enabled (returns __schema). That's a real exposure
 *      because attackers can enumerate every query/mutation + types.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";

interface Sig {
  name: string;
  re?: RegExp;
  header?: string;
  headerRe?: RegExp;
  bodyRe?: RegExp;
  cwe?: string[];
}

const SIGS: Sig[] = [
  { name: "WordPress",  bodyRe: /\/wp-(content|includes|json)\//i },
  { name: "Drupal",     bodyRe: /Drupal\.settings|<meta\s+name=\"Generator\"\s+content=\"Drupal/i },
  { name: "Joomla",     bodyRe: /\/media\/jui\/|name=\"generator\"\s+content=\"Joomla!/i },
  { name: "Magento",    bodyRe: /Mage\.Cookies|skin\/frontend\/|var\s+BASE_URL/i },
  { name: "Shopify",    headerRe: /Shopify/i, header: "x-shopid" },
  { name: "Next.js",    bodyRe: /__NEXT_DATA__|\/_next\//i },
  { name: "Nuxt",       bodyRe: /__NUXT__|window\.__NUXT__/i },
  { name: "Laravel",    headerRe: /laravel_session|XSRF-TOKEN/i, header: "set-cookie" },
  { name: "Django",     headerRe: /csrftoken|sessionid/i, header: "set-cookie", bodyRe: /name=\"csrfmiddlewaretoken\"/i },
  { name: "Spring",     headerRe: /JSESSIONID/i, header: "set-cookie" },
  { name: "Rails",      headerRe: /_session=/i, header: "set-cookie", bodyRe: /name=\"authenticity_token\"/i },
  { name: "Express",    headerRe: /express/i, header: "x-powered-by" },
  { name: "ASP.NET",    headerRe: /ASP\.NET/i, header: "x-powered-by" },
  { name: "Cloudflare", header: "cf-ray" },
  { name: "Akamai",     header: "akamai-grn" },
  { name: "Vercel",     headerRe: /vercel|now/i, header: "server" },
  { name: "Apache",     headerRe: /Apache/i, header: "server" },
  { name: "Nginx",      headerRe: /nginx/i, header: "server" },
];

const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];
const GRAPHQL_INTROSPECTION = JSON.stringify({
  query: "{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name}}}",
});

export const fingerprintScanner: Scanner = {
  id: "web.fingerprint",
  name: "Tech Fingerprint + GraphQL",
  kind: "web",
  description: "Detects CMS / framework / CDN signatures and probes /graphql variants for introspection-enabled endpoints.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.fingerprint",
      name: "Tech Fingerprint",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Built-in framework / CMS / CDN fingerprinter + GraphQL introspection check.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;

    let res: Response;
    let body: string;
    try {
      res = await fetch(url, { headers: { "User-Agent": "moba-scanner/0.1 (+fingerprint)" }, redirect: "follow", signal: ctx.signal });
      body = (res.headers.get("content-type") ?? "").includes("text") ? (await res.text()).slice(0, 200_000) : "";
    } catch (e) {
      await ctx.log("error", `fetch failed: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }

    await ctx.progress(0.4, "matching signatures");
    const detected: { name: string; via: string }[] = [];
    for (const s of SIGS) {
      let hit = false;
      let via = "";
      if (s.header) {
        const v = res.headers.get(s.header);
        if (v && (s.headerRe ? s.headerRe.test(v) : true)) { hit = true; via = `header ${s.header}: ${truncate(v, 120)}`; }
      }
      if (!hit && s.bodyRe && s.bodyRe.test(body)) { hit = true; via = "body match"; }
      if (hit) detected.push({ name: s.name, via });
    }

    if (detected.length) {
      await ctx.emit(draft({
        severity: "info",
        confidence: "medium",
        title: `Stack fingerprint: ${detected.map((d) => d.name).join(", ")}`,
        description: "Server stack identified from response signatures. Useful for CVE lookup; not a vulnerability by itself.",
        ruleId: "fingerprint/detected",
        location: { url: url.toString() },
        evidence: { detected },
      }));
    }

    // GraphQL introspection
    await ctx.progress(0.7, "graphql introspection");
    for (const p of GRAPHQL_PATHS) {
      if (ctx.signal.aborted) break;
      const probeUrl = new URL(p, url);
      try {
        const r = await fetch(probeUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "User-Agent": "moba-scanner/0.1 (+graphql)",
            ...(ctx.target.auth?.headers ?? {}),
          },
          body: GRAPHQL_INTROSPECTION,
          signal: ctx.signal,
        });
        if (!r.ok) continue;
        const text = await r.text();
        if (/__schema|queryType|mutationType/.test(text)) {
          await ctx.emit(draft({
            severity: "medium",
            confidence: "high",
            title: `GraphQL introspection enabled at ${p}`,
            description: "Production GraphQL endpoints should disable __schema introspection — it lets attackers enumerate every query, mutation, and type.",
            ruleId: "graphql/introspection",
            cwe: ["CWE-200"],
            owasp: ["A05:2021"],
            location: { url: probeUrl.toString() },
            evidence: { responseSnippet: truncate(text, 400) },
            remediation: "Disable introspection in production (e.g. Apollo `introspection: false`); gate explorer UIs behind auth.",
            references: ["https://owasp.org/www-project-api-security/"],
          }));
        }
      } catch { /* path absent */ }
    }
    await ctx.progress(1, "done");
  },
};

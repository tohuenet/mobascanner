/**
 * Tech / CMS fingerprint + GraphQL introspection — built-in.
 *
 * Three passes:
 *   1. Headers + body sniff — populates a list of detected stacks
 *      (WordPress, Drupal, Joomla, Shopify, Magento, Next.js, Laravel,
 *       Django, Spring, Rails, Express, ASP.NET, Cloudflare, …).
 *      Findings are info-level UNLESS the version is precise enough to
 *      look up CVEs.
 *   2. Live library/runtime VERSION extraction — pulls concrete `pkg@version`
 *      pairs out of the `Server` / `X-Powered-By` headers, `<meta generator>`,
 *      served JS bundles + inline globals, and an optionally-exposed
 *      `/package.json`. Emitted as one structured `fingerprint/live-versions`
 *      finding whose `evidence.liveVersions` is the runtime side of the
 *      correlation engine's version-reachability join (a vulnerable SCA
 *      dependency observed served live is reachable in production).
 *   3. Common API roots — checks /graphql, /api/graphql, /v1/graphql for
 *      introspection enabled (returns __schema). That's a real exposure
 *      because attackers can enumerate every query/mutation + types.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";

/**
 * A concrete library / runtime version observed on the LIVE application.
 * `version` is optional: high-confidence framework tokens (a `Server` /
 * `X-Powered-By` name) are worth recording even name-only, because their mere
 * presence lets the correlation engine avoid falsely deprioritizing a matching
 * SCA finding. The fuzzy sources (bundles/inline/meta/package.json) only ever
 * emit when a version actually parses.
 */
export interface LiveVersion {
  /** Normalized to lowercase. */
  pkg: string;
  version?: string;
  source: "header" | "meta" | "bundle" | "inline" | "package-json";
  ecosystem: "server" | "php" | "npm" | "generator";
}

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

// ─────────────────────── live version extraction ────────────────────────
//
// All pure/string — no network, no deps — so it is unit-testable in isolation
// and safe to call on whatever the single root fetch already returned.

/** At least major.minor; capture up to 4 numeric segments. Conservative on
 *  purpose — a lone integer ("2024") is too weak to trust as a version. */
const VER = "(\\d+\\.\\d+(?:\\.\\d+){0,2})";

/** Known client-side libraries we are willing to fingerprint from bundle
 *  filenames / CDN paths. An allowlist keeps the bundle parser precise (a
 *  random `analytics-2.0.js` is not a dependency we can CVE-map reliably). */
const KNOWN_LIBS = new Set<string>([
  "jquery", "jquery-ui", "jquery-migrate", "bootstrap", "angular", "angularjs",
  "vue", "react", "react-dom", "lodash", "underscore", "moment", "d3",
  "backbone", "ember", "knockout", "handlebars", "mustache", "axios", "popper",
  "popperjs", "gsap", "three", "chart", "chartjs", "select2", "datatables",
  "swiper", "slick", "alpine", "alpinejs", "htmx", "foundation", "modernizr",
  "requirejs", "zepto", "ramda", "rxjs", "redux", "tinymce", "ckeditor",
  "leaflet", "videojs", "hammer", "dropzone", "flatpickr", "fullcalendar",
  "highcharts", "echarts", "toastr", "sweetalert", "sweetalert2", "nprogress",
  "isotope", "masonry", "typed", "particles", "fancybox", "owl.carousel",
]);

/** Canonicalize a raw library token to its normalized package name. */
function canonLib(raw: string): string | undefined {
  const n = raw.toLowerCase().replace(/\.min$|\.slim$|\.pack$|\.bundle$/g, "");
  if (KNOWN_LIBS.has(n)) return n === "angularjs" ? "angular" : n === "chartjs" ? "chart.js" : n === "popperjs" ? "popper" : n === "alpinejs" ? "alpine" : n;
  return undefined;
}

/** Products in a `Server` / `X-Powered-By`-style header: `name/1.2.3`. */
function parseHeaderProducts(header: string, source: "header"): LiveVersion[] {
  const out: LiveVersion[] = [];
  const re = new RegExp(`([A-Za-z][A-Za-z0-9_.+-]*?)\\/${VER}`, "g");
  for (const m of header.matchAll(re)) {
    const pkg = m[1].toLowerCase();
    out.push({ pkg, version: m[2], source, ecosystem: pkg === "php" ? "php" : "server" });
  }
  return out;
}

/** `X-Powered-By`: parse `PHP/8.1.2`, else record the bare framework name
 *  (e.g. `Express`, `ASP.NET`) — the presence itself is a reliable signal. */
function parseXPoweredBy(value: string): LiveVersion[] {
  const withVer = parseHeaderProducts(value, "header");
  if (withVer.length) return withVer;
  const out: LiveVersion[] = [];
  for (const partRaw of value.split(",")) {
    const part = partRaw.trim();
    const nameM = /^([A-Za-z][A-Za-z0-9_.+ -]*)$/.exec(part);
    if (!nameM) continue;
    const pkg = nameM[1].trim().toLowerCase();
    if (!pkg) continue;
    out.push({ pkg, source: "header", ecosystem: /php/.test(pkg) ? "php" : "server" });
  }
  return out;
}

/** `<meta name="generator" content="WordPress 6.2.1">` → wordpress@6.2.1. */
function parseGenerator(body: string): LiveVersion[] {
  const out: LiveVersion[] = [];
  const metaRe = /<meta[^>]+name=["']generator["'][^>]*>/gi;
  for (const tag of body.matchAll(metaRe)) {
    const contentM = /content=["']([^"']+)["']/i.exec(tag[0]);
    if (!contentM) continue;
    const m = new RegExp(`^([A-Za-z][\\w .!+-]*?)[\\s/v]+${VER}`).exec(contentM[1].trim());
    if (!m) continue;
    const pkg = m[1].trim().replace(/\s+/g, " ").toLowerCase();
    if (pkg) out.push({ pkg, version: m[2], source: "meta", ecosystem: "generator" });
  }
  return out;
}

/** Versions from `<script src>` filenames and CDN paths (allowlisted libs). */
function parseScriptSrcs(body: string): LiveVersion[] {
  const out: LiveVersion[] = [];
  const fileRe = new RegExp(`^([a-z0-9][a-z0-9._-]*?)[-_.@]${VER}(?:[-.](?:min|slim|pack|prod|dev|umd|esm|cjs|bundle|module|browser|common))*\\.js$`);
  const cdnRe = new RegExp(`/(?:ajax/libs|npm|libs|packages|gh|cdn)/([a-z0-9._-]+?)[@/]${VER}(?:[/.]|$)`);
  // unpkg / jsdelivr root-level `name@version` (e.g. //unpkg.com/lodash@4.17.15/…).
  const atVerRe = new RegExp(`(?:^|/)([a-z0-9._-]+)@${VER}(?:[/.]|$)`);
  for (const m of body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    const src = m[1].toLowerCase();
    const base = src.split(/[?#]/)[0].split("/").pop() ?? "";
    let raw: string | undefined; let version: string | undefined;
    const fm = fileRe.exec(base);
    if (fm) { raw = fm[1]; version = fm[2]; }
    else {
      const cm = cdnRe.exec(src) ?? atVerRe.exec(src);
      if (cm) { raw = cm[1].split("/").pop(); version = cm[2]; }
    }
    if (!raw || !version) continue;
    const pkg = canonLib(raw);
    if (pkg) out.push({ pkg, version, source: "bundle", ecosystem: "npm" });
  }
  return out;
}

/** High-confidence inline version globals present in un-minified library src. */
function parseInlineGlobals(body: string): LiveVersion[] {
  const out: LiveVersion[] = [];
  const push = (pkg: string, m: RegExpExecArray | null) => { if (m) out.push({ pkg, version: m[1], source: "inline", ecosystem: "npm" }); };
  // jQuery exposes `jquery: "3.5.1"` on the prototype and `$.fn.jquery`.
  push("jquery", new RegExp(`["']?jquery["']?\\s*[:=]\\s*["']${VER}["']`, "i").exec(body)
    ?? new RegExp(`\\.fn\\.jquery\\s*=\\s*["']${VER}["']`, "i").exec(body));
  push("vue",    new RegExp(`Vue\\.version\\s*=\\s*["']${VER}["']`).exec(body));
  push("react",  new RegExp(`React\\.version\\s*=\\s*["']${VER}["']`).exec(body));
  push("moment", new RegExp(`moment\\.version\\s*=\\s*["']${VER}["']`).exec(body));
  return out;
}

/** Loose npm range → base version (`^4.17.21` → `4.17.21`); skip non-pins. */
function pinnedVersion(spec: string): string | undefined {
  const cleaned = spec.trim().replace(/^[v^~>=<\s]+/, "");
  const m = new RegExp(`^${VER}`).exec(cleaned);
  return m ? m[1] : undefined;
}

/** An exposed `/package.json` → its `dependencies` name→version map. */
function parsePackageJson(text: string): LiveVersion[] {
  const out: LiveVersion[] = [];
  let obj: unknown;
  try { obj = JSON.parse(text); } catch { return out; }
  if (!obj || typeof obj !== "object") return out;
  const deps = (obj as Record<string, unknown>).dependencies;
  if (!deps || typeof deps !== "object") return out;
  for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
    if (typeof spec !== "string") continue;
    const version = pinnedVersion(spec);
    if (version) out.push({ pkg: name.toLowerCase(), version, source: "package-json", ecosystem: "npm" });
  }
  return out;
}

const SOURCE_RANK: Record<LiveVersion["source"], number> = { header: 0, meta: 1, "package-json": 2, bundle: 3, inline: 4 };

/**
 * Combine every source into a deduped, deterministic list. Within a package we
 * prefer versioned entries over name-only, then the more reliable source, then
 * the earliest version string — so the output is stable regardless of match
 * order (important for the correlation engine's idempotency).
 */
export function extractLiveVersions(input: {
  server?: string | null;
  poweredBy?: string | null;
  body?: string;
  packageJsonText?: string | null;
}): LiveVersion[] {
  const all: LiveVersion[] = [];
  if (input.server) all.push(...parseHeaderProducts(input.server, "header"));
  if (input.poweredBy) all.push(...parseXPoweredBy(input.poweredBy));
  if (input.body) { all.push(...parseGenerator(input.body), ...parseScriptSrcs(input.body), ...parseInlineGlobals(input.body)); }
  if (input.packageJsonText) all.push(...parsePackageJson(input.packageJsonText));

  const best = new Map<string, LiveVersion>();
  for (const v of all) {
    const cur = best.get(v.pkg);
    if (!cur) { best.set(v.pkg, v); continue; }
    const better =
      (!!v.version && !cur.version) ||
      (!!v.version === !!cur.version && SOURCE_RANK[v.source] < SOURCE_RANK[cur.source]) ||
      (!!v.version === !!cur.version && v.source === cur.source && (v.version ?? "") < (cur.version ?? ""));
    if (better) best.set(v.pkg, v);
  }
  return [...best.values()].sort((a, b) => a.pkg.localeCompare(b.pkg) || (a.version ?? "").localeCompare(b.version ?? ""));
}

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

    // ── Live library / runtime versions (reachability signal) ──────────
    await ctx.progress(0.55, "extracting live versions");
    // Optional, low-risk GET of an exposed /package.json. Treated as content:
    // only fed to the parser when it actually looks like a JSON object; a 404
    // or an SPA index-shell is tolerated silently.
    let packageJsonText: string | null = null;
    try {
      const pjUrl = new URL("/package.json", url);
      const rj = await fetch(pjUrl, { headers: { "User-Agent": "moba-scanner/0.1 (+fingerprint)" }, redirect: "follow", signal: ctx.signal });
      if (rj.ok) {
        const t = (await rj.text()).slice(0, 100_000);
        if (t.trimStart().startsWith("{")) packageJsonText = t;
      }
    } catch { /* /package.json absent — fine */ }

    const liveVersions = extractLiveVersions({
      server: res.headers.get("server"),
      poweredBy: res.headers.get("x-powered-by"),
      body,
      packageJsonText,
    });
    if (liveVersions.length) {
      const precise = liveVersions.some((v) => !!v.version);
      const label = liveVersions.map((v) => (v.version ? `${v.pkg}@${v.version}` : v.pkg)).slice(0, 8).join(", ");
      await ctx.emit(draft({
        // `low` when a precise version is present (enables CVE lookup +
        // version-reachability correlation); otherwise purely informational.
        severity: precise ? "low" : "info",
        confidence: "medium",
        title: `Live library/runtime versions: ${label}${liveVersions.length > 8 ? " …" : ""}`,
        description:
          "Concrete versions extracted from live response headers, page markup, and served bundles. " +
          "The correlation engine joins these against SCA (source) findings — a vulnerable dependency " +
          "observed served live is confirmed reachable in production, not a theoretical dependency alert.",
        ruleId: "fingerprint/live-versions",
        location: { url: url.toString() },
        evidence: { liveVersions },
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

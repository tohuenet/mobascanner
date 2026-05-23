// Standalone verification of the new content-discovery filter against a live
// target. Replicates the new probe + baseline-match logic and prints a
// pass/fail per case. Deletes itself out of git after manual review.
//
// Run: node scripts/verify-fix.mjs [target-url]

const TARGET = process.argv[2] || "https://widata.vn";

function cheapHash(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

function fingerprint(body, pathToken) {
  const norm = body
    .split(pathToken).join("")
    .replace(/\d+/g, "")
    .replace(/\s+/g, " ")
    .slice(0, 2048);
  return `${norm.length}:${cheapHash(norm)}`;
}

async function probePath(base, p) {
  const url = `${base}/${p}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "User-Agent": "moba-scanner/0.1 (+verify)" },
      redirect: "follow",
    });
    const body = (await res.text().catch(() => "")).slice(0, 4096);
    const clen = Number(res.headers.get("content-length"));
    const len = Number.isFinite(clen) && clen > 0 ? clen : body.length;
    return {
      url,
      status: res.status,
      finalUrl: res.url,
      len,
      sig: fingerprint(body, p || "/"),
    };
  } catch (e) {
    return { url, error: String(e) };
  }
}

function matchesBaseline(p, baselines) {
  return baselines.some((b) =>
    p.status === b.status &&
    (p.sig === b.sig || Math.abs(p.len - b.len) <= Math.max(64, b.len * 0.05)));
}

const rnd = () => Math.random().toString(36).slice(2, 12);

console.log(`Target: ${TARGET}\n`);

const baselineProbes = [rnd(), `${rnd()}/`, ""];
const baselines = [];
for (const p of baselineProbes) {
  const r = await probePath(TARGET, p);
  console.log(`baseline "/${p}" → status=${r.status} final=${r.finalUrl} len=${r.len} sig=${r.sig}`);
  baselines.push(r);
}
console.log();

// Cases: filter = false positive must be suppressed; keep = real path must
// surface (either as Path-reachable or as auth-gated). Picked to match BOTH
// widata.vn (catch-all SPA) and the local vuln-target.mjs.
const SUITE = process.argv[3] || "widata"; // "widata" | "vuln"
const cases = SUITE === "vuln" ? [
  // No-regression: real exposures on the intentional vuln target.
  { p: ".env",                 expect: "keep"   },
  { p: ".git/config",          expect: "keep"   },
  { p: "server-status",        expect: "keep"   },
  { p: "admin",                expect: "keep"   }, // 403 → auth-gated branch
  { p: "zzz-not-real-9f8a/",   expect: "filter" },
  { p: "wp-admin/",            expect: "filter" }, // vuln-target has no wp-admin
] : [
  // SPA catch-all false-positive class.
  { p: "wp-admin/",            expect: "filter" },
  { p: "phpmyadmin/",          expect: "filter" },
  { p: "joomla/administrator/", expect: "filter" },
  { p: "admin/",               expect: "filter" },
  { p: "administrator/",       expect: "filter" },
  { p: "zzz-not-real-9f8a/",   expect: "filter" },
  { p: "robots.txt",           expect: "keep"   },
  { p: "sitemap.xml",          expect: "keep"   },
];

let pass = 0, fail = 0;
for (const c of cases) {
  const r = await probePath(TARGET, c.p);
  const isHardNF = r.status === 404 || r.status === 410;
  const offHost = (() => {
    try { return new URL(r.finalUrl).host !== new URL(TARGET).host; } catch { return false; }
  })();
  const matchesB = matchesBaseline(r, baselines);
  const filtered = isHardNF || offHost || matchesB;
  const actual = filtered ? "filter" : "keep";
  const ok = actual === c.expect;
  console.log(`${ok ? "PASS" : "FAIL"} /${c.p.padEnd(30)} status=${r.status} len=${r.len} sig=${r.sig}  → ${actual}  (expected ${c.expect})`);
  if (ok) pass++; else fail++;
}
console.log(`\n${pass} pass / ${fail} fail`);
process.exit(fail ? 1 : 0);

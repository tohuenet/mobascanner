# moba-scanner

A self-hosted security console that wraps best-in-class open-source tooling
behind a single normalized findings feed. Two modes:

| Mode | Style | What it does |
| ---- | ----- | ------------ |
| **Web pentest** | Acunetix-like (DAST) | Crawl a live target, inspect TLS / cookies / headers, run nuclei templates |
| **Source pentest** | SonarQube-like (SAST/SCA) | Pull source from a git URL or local path; scan for secrets, CVEs in deps, IaC misconfigs, static analysis findings |

The UI follows **Material Design 3** tokens layered with a **Liquid Glass**
surface treatment (translucent panels, soft edge highlights, subtle gradients).

## Quick start

```bash
npm install
npm run dev   # http://localhost:3000
```

The home page has buttons for the two scan modes. No external scanner is
required to get started — the built-in adapters (Security Headers, Cookies,
TLS, HTML Crawler, Regex Secrets) cover ~70% of the catalog.

## Architecture

```
app/                            Next.js 16, App Router
  page.tsx                      Dashboard
  scan/web                      POST /api/scans (kind=web) → SSE → ScanDetailClient
  scan/source                   POST /api/scans (kind=source)
  scans/[id]                    server fetch + client SSE merge
  api/scans                     create / list
  api/scans/[id]                GET full scan + findings, DELETE
  api/scans/[id]/stream         SSE — scanner-progress, finding, scan-finished
  api/tools                     live availability of every adapter
lib/                            engine + adapters
  types.ts                      Severity, Finding, Scan, ScanEvent (SSE discriminator)
  store.ts                      JSON-file persistence (data/scans/<id>/{scan.json,findings.jsonl})
  engine/                       scanner interface, global registry, orchestrator + event bus
  scanners/web/                 headers · cookies · tls · crawler · nuclei
  scanners/source/              regex-secrets · semgrep · gitleaks · trivy · git-import
  scanners/common.ts            cross-spawn-based runCli, walkFiles, detectCli
```

## OWASP Top 10 (2021) — coverage matrix

| Item | Built-in scanner | CLI-backed |
|------|------------------|------------|
| **A01 Broken Access Control** | open-redirect + path-traversal probes (`web.active-injection`) | nuclei, ZAP |
| **A02 Cryptographic Failures** | `web.tls`, `web.headers` (HSTS/CSP), `web.crawler` (mixed content) | testssl.sh (TODO) |
| **A03 Injection** | `web.active-injection` (XSS/SQLi/CMD/LFI), `source.regex-secrets` | sqlmap, wapiti, nuclei, semgrep, bandit, brakeman |
| **A04 Insecure Design** | `web.fingerprint` + `web.content-discovery` (surfaces design leaks) | semgrep custom rules |
| **A05 Security Misconfig** | `web.headers`, `web.cors`, `web.cookies`, `web.ports`, `web.content-discovery`, `web.fingerprint` (GraphQL introspection) | nuclei, nikto, checkov, trivy IaC |
| **A06 Vulnerable Components** | — | trivy, osv-scanner, nuclei CVE templates |
| **A07 Auth/Session Failures** | `web.jwt`, `web.cookies`, `source.regex-secrets` | gitleaks, nuclei |
| **A08 Software/Data Integrity** | `web.cookies` (SameSite), `source.regex-secrets` (signing keys) | trivy SBOM, osv-scanner |
| **A09 Logging/Monitoring** | (out of scope — runtime not source/DAST) | — |
| **A10 SSRF** | `web.active-injection` (AWS IMDS probe), `web.crawler` (URL inventory) | nuclei, ZAP |

## Scanners shipped

### Web (DAST) — built-in
The web pipeline is **SiteMap-driven**. `web.crawler` runs first and builds a
`SiteMap` (pages, forms, cookies, JS-mined endpoints) saved at
`data/scans/<id>/sitemap.json`. Every other web scanner reads it so coverage
is **per-URL**, not just the seed.

| Adapter | Notes |
|---------|-------|
| `web.crawler` | **Foundation.** BFS deep crawl, form extraction, JS endpoint mining, cookie tracking via BrowsingSession. Builds the SiteMap. |
| `web.headers` | OWASP Secure Headers (HSTS, CSP, X-Frame-Options, COOP) — checked across **every URL** in the SiteMap, results aggregated. |
| `web.cookies` | Secure / HttpOnly / SameSite flags across all observed Set-Cookie events during the crawl. |
| `web.tls` | TLS handshake, weak protocol, expired cert, untrusted chain. |
| `web.ports` | TCP-connect scan over ~60 high-signal ports (DBs, mgmt panels, RDP, …). |
| `web.cors` | Origin reflect, null origin, prefix/suffix bypass, wildcard+credentials. |
| `web.jwt` | alg=none, missing exp, kid traversal, PII in payload. |
| `web.fingerprint` | CMS / framework / CDN sniff + GraphQL introspection probe. |
| `web.content-discovery` | Curated 250-path dirbust (.git, .env, swagger, actuator, admin, backups…). |
| `web.active-injection` | XSS / error+time SQLi / LFI / cmd-injection / SSRF / open-redirect probes against **every parameter** discovered by the crawler. JSON-aware (won't false-flag echoed JSON as XSS). |
| `web.subdomain-enum` | crt.sh + DNS dictionary; flags dev/staging/admin envs. |
| `web.form-fuzzer` | Submits **every form** in the SiteMap with XSS/SQLi/LFI/cmd-injection probes per non-CSRF input. Skips login forms. |
| `web.brute-login` | Tries ~25 default-credential pairs (admin/admin, root/root, …) against every login form. |
| `web.verb-tampering` | For URLs that returned 401/403/405, retries with HEAD/OPTIONS/PUT/DELETE/PATCH/TRACE + `X-HTTP-Method-Override` header. Detects access-control-by-method bypass. |
| `web.idor` | Walks numeric ids in URL paths / query (`/users/123`, `?id=42`), probes id±{1,2,10,100}, flags endpoints that return distinct content without auth gate. |
| `web.param-miner` | Probes ~120 candidate parameter names against high-interest URLs to discover hidden GET params (debug flags, file loaders, redirect targets). |

### Web (DAST) — external CLI / API
| Adapter | Upstream |
|---------|----------|
| `web.nuclei` | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) — thousands of CVE / misconfig templates |
| `web.nmap` | [nmap](https://nmap.org) — top-1000 TCP-connect with service/version |
| `web.ffuf` | [ffuf/ffuf](https://github.com/ffuf/ffuf) — exhaustive content discovery |
| `web.zap` | [OWASP ZAP](https://www.zaproxy.org) (REST API to a running daemon) |
| `web.wapiti` | [wapiti-scanner/wapiti](https://github.com/wapiti-scanner/wapiti) |
| `web.nikto` | [sullo/nikto](https://github.com/sullo/nikto) — 6700+ checks for legacy issues |
| `web.sqlmap` | [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) — SQLi exploitation |
| `web.testssl` | [drwetter/testssl.sh](https://github.com/drwetter/testssl.sh) — deep TLS audit |
| `web.subfinder` | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) — passive subdomain enum |
| `web.httpx` | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) — URL probing + tech detect |
| `web.katana` | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) — JS-aware crawler |
| `web.naabu` | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) — fast port scanner |
| `web.masscan` | [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) — internet-scale port scan |
| `web.dastardly` | [PortSwigger Dastardly](https://www.portswigger.net/burp/dastardly) — Burp scan engine via Docker |

### Source (SAST/SCA) — built-in
| Adapter | Notes |
|---------|-------|
| `source.regex-secrets` | High-precision regex sweep (AWS, GitHub, Stripe, JWT, OpenAI, private keys) |

### Source (SAST/SCA) — external CLI
| Adapter | Upstream |
|---------|----------|
| `source.semgrep` | [semgrep/semgrep](https://github.com/semgrep/semgrep) — multi-language static analysis |
| `source.gitleaks` | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) — git-history secret sweep |
| `source.trivy` | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) — CVE deps + IaC + secrets |
| `source.osv-scanner` | [google/osv-scanner](https://github.com/google/osv-scanner) — OSV.dev-backed dep CVEs |
| `source.bandit` | [PyCQA/bandit](https://github.com/PyCQA/bandit) — Python SAST |
| `source.brakeman` | [presidentbeef/brakeman](https://github.com/presidentbeef/brakeman) — Ruby on Rails SAST |
| `source.eslint-security` | [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) — JS/TS |
| `source.checkov` | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) — Terraform / K8s / CFN IaC |
| `source.codeql` | [github/codeql](https://github.com/github/codeql) — heavyweight semantic SAST |
| `source.trufflehog` | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — verified secrets |
| `source.detect-secrets` | [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) — entropy-based secrets |
| `source.snyk` | [snyk/cli](https://github.com/snyk/cli) — Snyk Open Source + Snyk Code |
| `source.dependency-track` | [DependencyTrack](https://github.com/DependencyTrack/dependency-track) — SBOM upload + CVE intel |

## Beyond raw scanners

### Chain detection
After scanners finish, a built-in rules engine combines findings into
composite "this is the actual exploit path" findings — e.g. *XSS + cookie
without HttpOnly = critical session-hijack chain*. Rules live in
`lib/triage/chains.ts`; add yours by extending the `RULES` array.

### LLM triage
`POST /api/scans/<id>/triage` runs every finding through Claude (Haiku 4.5
by default) to:
- Filter false positives
- Adjust severity given context
- Generate an attacker-narrative + remediation snippet

Set `ANTHROPIC_API_KEY` to enable. Override the model with `TRIAGE_MODEL`.
Prompt caching is enabled, so cost stays low across re-runs.

### SARIF export
`GET /api/scans/<id>/sarif` returns a SARIF 2.1.0 document compatible with
GitHub Code Scanning, Azure DevOps, and most security dashboards. Upload via
`gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs` to surface
findings as repo-level alerts.

See [`ROADMAP.md`](ROADMAP.md) for the larger feature backlog.

CLIs not on `PATH` are auto-detected as **missing** in the UI. The scan still
runs — those adapters are skipped with a log line. Install via:

| Tool | macOS | Linux | Windows |
|------|-------|-------|---------|
| nuclei | `brew install nuclei` | GitHub releases | GitHub releases |
| semgrep | `brew install semgrep` | `pip install semgrep` | `pip install semgrep` (wsl recommended) |
| gitleaks | `brew install gitleaks` | GitHub releases | GitHub releases |
| trivy | `brew install trivy` | `apt install trivy` | GitHub releases |

## Adding a new scanner

```ts
// lib/scanners/web/my-scanner.ts
import { draft, type Scanner } from "../../engine/scanner";

export const myScanner: Scanner = {
  id: "web.my-scanner",
  name: "My Scanner",
  kind: "web",
  description: "What it does, in one line.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.my-scanner",
      name: "My Scanner",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "...",
      upstream: "https://...",
      license: "MIT",
    };
  },

  async run(ctx) {
    await ctx.progress(0.1, "starting");
    await ctx.emit(draft({
      severity: "high",
      title: "Example finding",
      description: "...",
      ruleId: "my-scanner/rule-1",
      cwe: ["CWE-79"],
      location: { url: ctx.target.value },
    }));
    await ctx.progress(1, "done");
  },
};
```

Then register in `lib/scanners/index.ts`. Findings stream via the bus → SSE →
UI as they're emitted.

## Persistence

Scans live under `data/scans/<id>/`:

- `scan.json` — status, target, per-scanner progress, severity counts
- `findings.jsonl` — append-only, one Finding per line
- `logs.jsonl` — append-only diagnostic log

Cloned source repos live under `data/repos/<scanId>/`. Both directories are
git-ignored. Delete with `DELETE /api/scans/<id>`.

## Scope, limits, ethics

- **Authorization**: only scan targets you own or have written permission to
  test. Web scanning sends real traffic.
- **Triage layer**: findings are normalized + deduplicated by `scanner+ruleId+location`,
  but the optional LLM-triage hook (`Finding.triage`) is left for the next iteration.
- **Shared browser session**: the bot currently parallel-crawls a user-driven
  browser by sharing the same seed URL + auth headers / cookies on the scan form.
  A Playwright + CDP shared-context implementation is planned in `lib/browser/`.

## License

The project itself is MIT. Each wrapped open-source tool retains its own
license — see the `tool()` metadata on each adapter.

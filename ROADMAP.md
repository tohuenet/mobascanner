# moba-scanner — roadmap

This document is the *honest* list of what's done, what's partly done, and
what would make the tool genuinely competitive with Acunetix / SonarQube
class commercial scanners.

Use it as a backlog: each item links to a concrete next step.

## Done

### Engine
- ☑ Adapter contract + global registry + scan orchestrator
- ☑ Streaming findings via SSE event bus
- ☑ JSON-file persistence (scans, findings, logs)
- ☑ Cross-spawn-based CLI runner (no shell-injection vector)
- ☑ Chain-detection rules engine (composite findings post-scan)

### Web (DAST) — 25 adapters
- ☑ Built-in: headers, cookies, tls, crawler, ports, cors, jwt, fingerprint,
  content-discovery, active-injection, subdomain-enum
- ☑ External CLI: nuclei, nmap, ffuf, ZAP (REST), wapiti, nikto, sqlmap,
  testssl.sh, subfinder, httpx, katana, naabu, masscan, Dastardly

### Source (SAST/SCA) — 13 adapters
- ☑ Built-in: regex-secrets
- ☑ External CLI: semgrep, gitleaks, trivy, osv-scanner, bandit, brakeman,
  eslint-security, checkov, CodeQL, TruffleHog, detect-secrets, Snyk
- ☑ External API: Dependency-Track (SBOM upload + findings sync)

### UI / UX
- ☑ Material 3 + Liquid Glass design system (light + dark, mobile responsive)
- ☑ Dashboard, web/source scan forms, scan detail w/ realtime SSE
- ☑ SARIF export (GitHub Code Scanning compatible)
- ☑ LLM triage button (uses Anthropic API)

## High-leverage next steps

These are the things that would meaningfully change the product, ranked by
user-visible impact.

### 1. Authenticated scanning — login recorder
**Today:** the scanner sends raw probes; if the target requires auth, all
authenticated paths are invisible. **Fix:**
- Add a Playwright "login recorder" page (`/scan/web/auth-record`).
- Open a real Chromium tab, let the user log in once.
- Persist the resulting cookie jar + storageState as a `LoginProfile`.
- Replay before each scanner via `target.auth.profile`.
- Periodically re-validate the session, re-login if expired.

This is what makes ZAP / Burp / Acunetix actually find anything in real apps.

### 2. Shared browser session (real implementation)
**Today:** the bot crawls the seed URL with header-only auth. **Fix:**
- Spin up Playwright with `chromium.launchServer({ port: 9222 })`.
- User joins via embedded `noVNC` viewer at `/browser/<scanId>`.
- Bot and user share **the same browser context** — same cookies, same
  service workers, same WebStorage.
- User does the human flow (e.g. complex multi-step checkout); bot picks
  up every URL/parameter the user touches and feeds them into the scanner
  parameter surface.

### 3. MITM intercepting proxy
**Today:** scanners only see what they fetch directly. **Fix:**
- Add a `lib/proxy/mitm.ts` based on `mockttp` or a custom Node TLS-MITM.
- Generate a per-user CA, instruct the user to install it.
- Spawn the proxy on `:8888`, point browser at it.
- Stream every request/response into the scan's evidence store.
- Replay each captured request with mutation (XSS/SQLi/IDOR payloads).

This lifts coverage on JS-heavy SPAs that the static crawler can't follow.

### 4. Authenticated source pull
**Today:** only public git URLs. **Fix:**
- Per-user GitHub/GitLab token vault (encrypted with `crypto.subtle`).
- Branch / PR / monorepo-package picker.
- Diff-only mode: scan only files changed in a PR.

### 5. CI/CD integration
**Today:** runs locally only. **Fix:**
- GitHub Action wrapper: pulls a docker image, posts findings as PR comments
  + Code Scanning alerts (we already export SARIF — wire it up).
- Quality gate: fail the build if new critical/high finding.
- Baseline diff: ignore findings present in the parent commit.

### 6. API-aware scanning (BOLA, mass-assignment, rate-limit)
**Today:** active-injection only fuzzes URL params. **Fix:**
- Import `openapi.json` / Postman collection / HAR file.
- For each `(operation, parameter)` pair, generate:
  - BOLA tests (swap your-id for someone-else's-id, expect 403)
  - Mass-assignment (POST extra fields, see if the server accepts)
  - Rate limit (burst N requests, watch for 429)
  - HTTP verb tampering
- Tag findings with the OpenAPI `operationId` for clean reporting.

### 7. Full GraphQL fuzzer
**Today:** introspection check only. **Fix:**
- After introspection, auto-generate one query per Type field.
- Detect:
  - Field-level auth bypass (call `User.email` on someone else's id)
  - Batching / aliasing DoS (1 request, N queries)
  - Depth-bomb / circular fragment (server should reject)
  - Cost-limit bypass

### 8. DOM-based XSS via headless browser
**Today:** XSS scanner only matches reflection in initial HTML. **Fix:**
- Spawn Chromium per probe, eval payload via `page.goto(URL_WITH_PAYLOAD)`.
- Hook `document.cookie`, `eval`, `innerHTML`, `Function` for taint.
- Detect XSS that only fires after JS runs (DOM XSS).

### 9. Race condition / TOCTOU tester
**Today:** none. **Fix:**
- For each "transaction" endpoint (transfer, redeem coupon, vote),
  send N parallel HTTP/2 requests with PortSwigger's "single-packet attack"
  (last byte trick) and look for double-spend in the response.

### 10. WebSocket security
**Today:** none. **Fix:**
- Detect WS upgrade, replay handshake from a foreign Origin.
- Fuzz frame payloads against the typed message handlers.
- Check for auth-on-upgrade vs auth-on-message confusion.

### 11. Compliance reports
**Today:** SARIF export only. **Fix:**
- Map findings → PCI-DSS / HIPAA / SOC 2 / ISO 27001 controls.
- One-click PDF "executive summary" generator.
- "Pass / Conditional / Fail" verdict per control.

### 12. Notification + ticketing integration
- Slack/Discord webhook on scan complete (or only-on-critical).
- Auto-create JIRA / Linear / GitHub issues for new criticals.
- De-dupe by `ruleId+location` so re-runs don't spam.

### 13. Time-series + diff
- Switch JSON-file store → SQLite for easy querying.
- Per-target trend chart (severity counts over time).
- "What's new since last scan" diff view.

### 14. Auth + multi-tenant
- User accounts, RBAC, per-org workspaces.
- Single-tenant vs hosted modes.
- API tokens for CLI / CI.

### 15. Threat-intel integration
- VirusTotal / Shodan / Censys / AbuseIPDB lookup on each open port.
- "This server has been seen running a known-vulnerable Confluence build
  for 3 days according to Shodan."

### 16. Cloud config audit
- AWS: prowler / Scout Suite wrapper.
- GCP: Forseti / Cloud Asset Inventory.
- Azure: ScubaGear.
- K8s: kube-bench / kube-hunter.

### 17. Container + image scanning
- Trivy already in. Add: dive, dockle, hadolint, syft + grype.
- Scan registry for old images, drift between repo and deployed.

### 18. Mobile (APK / IPA)
- MobSF wrapper for static + dynamic Android/iOS analysis.
- Scope: low priority unless the user has mobile in fleet.

### 19. AI-driven exploitation chain
- Beyond triage: let the LLM **propose the next probe** based on what's
  been seen so far. E.g. "I see open elasticsearch, no auth → probe
  `/_cat/indices` next." Sandboxed, dry-run by default.

### 20. Custom rule engine
- DSL for users to add rules without touching TypeScript.
- Example: "Find every URL with `?redirect=` and where the response
  Location header equals my probe value."
- Exposes the same `Finding` interface scanners use.

## Smaller wins (good first issues)

- ☐ Add `.well-known/security.txt` checker (built-in).
- ☐ Add weak-password / default-cred login probe (against /login + admin paths).
- ☐ HSTS preload list lookup (https://hstspreload.org/api/v2/status).
- ☐ DMARC / SPF / DKIM check (built-in DNS).
- ☐ Open S3 bucket / Azure blob detector.
- ☐ Source-side: lockfile-lint (npm), pip-audit, cargo-audit, govulncheck.
- ☐ License compliance scanner (scancode-toolkit / fossa).
- ☐ Schedule recurring scans (cron + persistence).
- ☐ Email digest: daily severity counts.
- ☐ Light/dark theme toggle in UI (currently follows OS).
- ☐ "Run scan against my localhost" shortcut on dashboard.

## Architectural improvements

- ☐ Move from single-process runner → BullMQ / Redis queue, so big scans
  don't block dev-time HMR.
- ☐ Scanner sandbox via worker_threads for built-in scanners.
- ☐ Resource budgets per scanner (CPU time, mem, network bytes).
- ☐ Pluggable triage backends (Claude today; OpenAI / local Ollama later).
- ☐ Webhook receiver for Dependency-Track / GitHub Advisory Database deltas
  → auto-rescan affected projects.

# Future directions

Honest, prioritized roadmap of what would make moba-scanner *clearly* beat
ZAP / Burp / Acunetix on every axis. Items are ordered by **leverage** (how
much they change the product), not by ease.

## Tier 1 — Game-changers

### 1. Authenticated session via Playwright login recorder
**Today:** scanner only sees what an unauthenticated user sees. Most real-world
vulns are post-login (BAC, IDOR, mass-assignment, race condition).
**Proposal:**
- New `/scan/auth-recorder` page: opens a real Chromium tab via Playwright.
- User logs in once.
- We capture `storageState` (cookies + localStorage + service workers).
- Persist as a `LoginProfile` (encrypted with `crypto.subtle`).
- Every subsequent scan replays the profile before launching scanners; the
  crawler / SQLi / form-fuzzer / IDOR / etc. all use the authenticated context.
- Re-validate session before each scanner; auto re-login if expired.

**Effort**: ~600 LoC + Playwright dep (~150MB chromium binary).
**Win**: changes coverage from "anonymous attack surface" to "real attack surface".

### 2. Shared user+bot browser session (real)
**Today:** "shared browser" is in our marketing but we only share auth headers.
**Proposal:**
- Spawn Playwright with `chromium.launchServer({ port })`.
- Inject noVNC viewer at `/browser/<scanId>` so user joins the same Chromium.
- Bot follows user navigation in real time; every URL/parameter/form the user
  touches feeds the scanner queue.
- Combined with #1: user does the human flow, bot fuzzes everything they touch.

**Effort**: ~800 LoC + Playwright + noVNC (~50MB).
**Win**: kills the "scanner can't navigate this SPA" problem entirely.

### 3. OOB collaborator service (interact.sh wrapper)
**Today:** blind RCE / blind SSRF / blind XSS / blind XXE all need an external
oracle to confirm. We don't have one — so we miss anything that doesn't echo
back synchronously.
**Proposal:**
- Bundle `interactsh-client` as a CLI adapter; spawn a per-scan canary domain.
- Inject the canary in JNDI / SSRF / blind-XSS / blind-XXE payloads.
- Poll the collaborator for DNS / HTTP / SMTP callbacks.
- Auto-link any hit back to the originating finding.

**Effort**: ~300 LoC (mostly polling glue).
**Win**: covers the full "blind" attack family — Log4Shell-style OOB RCE,
DNS-exfil SQLi, blind SSRF to internal services, etc.

### 4. Custom rule DSL
**Today:** new probes require TypeScript + a new file.
**Proposal:**
- YAML rule format inspired by nuclei templates but simpler.
- `lib/scanners/custom-runner.ts` loads rules from `rules/` dir.
- Each rule: `match` (HTTP request to send) + `assert` (regex / status / latency).
- Hot-reload during `next dev`.
- Ship a starter pack of ~50 rules covering common WordPress / Drupal / etc.
  exposures — overlaps with nuclei but works without the binary.

**Effort**: ~400 LoC.
**Win**: empowers users + security teams to ship fast without touching code.

### 5. AI-driven attack-chain executor
**Today:** LLM triage is post-hoc — it explains findings, doesn't extend them.
**Proposal:**
- Inject the LLM into the scanner loop: after every wave, send the findings
  set to Claude with the prompt "what's the next probe that has highest
  expected information gain?"
- Sandbox: LLM emits a JSON probe spec (URL, method, headers, body, expected
  marker); the runner executes only if it passes a safety policy (no destructive
  payloads, only the target host, rate-limited).
- Caches probe templates so repeat scans are cheap.

**Effort**: ~500 LoC + careful prompt + safety policy.
**Win**: scanner that adapts to the target instead of running a fixed playbook.

## Tier 2 — Operational

### 6. CI/CD GitHub Action wrapper
- Docker image of moba-scanner.
- Action: spin up scanner, scan target, post SARIF to GitHub Code Scanning.
- Supports `pr-diff` mode using our `/api/scans/[a]/diff/[b]` endpoint.
- Quality gate: fail build if new critical/high.

### 7. Schedule scans (cron)
- `lib/schedule/cron.ts` with persistent next-run timestamps.
- Per-target schedule (daily / weekly).
- Email / Slack digest with diff vs previous run.

### 8. Slack / Discord / JIRA / Linear webhooks
- Post on scan complete OR only on new criticals.
- De-dupe by `(rule, location)` so re-scans don't spam.
- Auto-create JIRA ticket for new criticals; auto-close when fixed.

### 9. MITM proxy mode
- `lib/proxy/mitm.ts` based on `mockttp` (no native deps).
- Generate per-user CA; user installs root.
- Proxy on `:8888`; user browses through it.
- Every request → SiteMap + replay queue.
- Lifts coverage on JS-heavy SPAs that the static crawler can't follow.

### 10. Multi-tenant + RBAC
- User accounts (NextAuth.js).
- Per-org workspaces; per-user API tokens.
- Reading vs writing permissions.

### 11. Time-series store
- Migrate JSON files → SQLite via `better-sqlite3`.
- Per-target trend chart (severity counts over time).
- "Risk score over the last 90 days".

## Tier 3 — Coverage extensions

### 12. DOM XSS via headless Chrome
- Per-finding: re-fire the XSS payload in a fresh Chromium tab.
- Hook `document.cookie` / `eval` / `innerHTML` / `Function` for taint.
- Detect XSS that only fires after JS executes.

### 13. Mobile static analysis (MobSF)
- Upload APK → MobSF → SARIF mapping.
- iOS IPA support.

### 14. Cloud-config audit (Prowler / Scout Suite / kube-bench)
- Adapter wrappers — same pattern as nuclei adapter.
- Map to our normalized Finding schema.
- Combine with K8s-API scanner so cluster + apps in one report.

### 15. Container / image scanning
- Beyond trivy: dive (layer analysis), dockle (CIS bench), hadolint.
- Registry scan for old images, drift between repo & deployed.

### 16. Threat-intel integration
- VirusTotal / Shodan / Censys / AbuseIPDB lookups on each open port + cert.
- "This server has been seen running a vulnerable Confluence build for 3 days
  according to Shodan."

### 17. SBOM diff between scans
- Track package additions / removals / version drift.
- Alert on new dependency that introduces a known-vuln transitive.

### 18. Compliance mode
- Map findings → PCI-DSS / HIPAA / SOC 2 / ISO 27001 controls.
- One-click PDF executive summary.
- Per-control "Pass / Conditional / Fail" verdict.

## Tier 4 — Niche but valuable

### 19. Browser extension for live capture
- "Mark this as a target" in the user's real browser.
- Captures the current request + auth state.
- Fires a scan against just that endpoint — useful for QA / bug-bounty hunters.

### 20. Diff-only PR scanning
- Given `git diff <base> <head>`, scan only files changed.
- Skip findings that exist on `<base>` (use our scan-diff endpoint).

### 21. Custom payload library (per target)
- Per-target scanner config: "this target uses GraphQL, focus there."
- Auto-tuned probe budgets per scanner.

### 22. Real-time HTTP capture during crawl
- Persist every request/response pair (HAR-shaped) in `data/scans/<id>/traffic.har`.
- UI shows the request/response evidence inline with findings.
- Replay any captured request from the UI (Burp Repeater equivalent).

### 23. Auto-update nuclei templates
- Daily `nuclei -update-templates` cron.
- Watch the upstream repo; surface new templates as "new probes available".

### 24. Per-finding patch generation (LLM)
- For source findings: ask Claude for a unified-diff fix.
- Show as PR-ready patch alongside the finding.
- For web findings: generate the WAF rule / Nginx config / CSP.

### 25. Heuristic regression-finding ranker
- After dedup, rank by ROI: severity × (1 - age) × exploitability score.
- LLM tags each finding with "exploit complexity" + "data sensitivity"
- Top-of-feed = the 5 things to fix this week.

## Items I considered and explicitly punted

- **Mobile dynamic analysis** (Frida instrumentation) — too platform-specific.
- **Hardware / IoT scanning** — orthogonal product.
- **Network packet captures** — Wireshark already exists.
- **Custom WAF / RASP** — moba-scanner is a scanner, not runtime defense.
- **Pen-tester chatbot** — model availability + safety > implementation effort.
  But this fits a thin-skill in Claude Agent SDK; could ship as a side product.

## Suggestions you might not have considered

1. **Per-scanner cost dashboards** — "your last scan made 3,200 HTTP requests
   and 12,000 LLM tokens; here's the breakdown by scanner." Helps tune which
   scanners to disable on large targets.

2. **Polite-mode global rate limiter** — token bucket per origin so we don't
   accidentally DoS small targets. Especially important for the active
   scanners (form-fuzzer, brute-login).

3. **"Curiosity bonus"** — when the LLM triage layer flags a finding as
   `needs_confirmation`, automatically schedule the active-injection scanner
   to re-probe that exact location with deeper payloads.

4. **Bug-bounty mode** — preset that runs only the high-confidence,
   non-destructive scanners; tuned for in-scope domains; auto-generates a
   HackerOne-style report markdown.

5. **Compliance scope toggles** — "Scan only PCI-DSS-relevant findings" =>
   filter findings to those mapped to PCI controls.

6. **Continuous attack surface monitoring** — daily passive recon (DNS audit,
   subdomain enum, HSTS preload, cert transparency) against a list of seed
   domains. Alert on new subdomains, new certs, new open ports.

7. **Encrypted target inventory** — store target lists + auth profiles
   encrypted at rest. Accidental leak of `data/` shouldn't dump customer
   credentials.

8. **Scan annotation / markdown notes** — let users attach context to
   findings ("this is the SSO subdomain, scope here is wider"). Surface in
   reports.

9. **Replay attack timeline** — for race-condition findings, render an
   ASCII waterfall diagram of the parallel requests so users can see exactly
   what happened.

10. **"Why is this finding here?"** — for every finding, store a 1-paragraph
    explanation: which scanner, which probe, which baseline comparison passed.
    Saves triage time enormously.

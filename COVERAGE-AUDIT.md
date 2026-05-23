# Coverage audit — what's there, what's missing

This is the brutally honest list. ✅ shipped, 🟡 partial, ❌ missing.
"Missing" doesn't mean useless — most are gaps everyone has; this lets us
target the highest-ROI ones next.

## 1. Discovery & reconnaissance

| Method | Status |
|---|---|
| Deep BFS crawler with form / link / script extraction | ✅ |
| robots.txt + sitemap.xml + .well-known seeding | ✅ |
| JS endpoint mining (`/api/...` literals, `fetch("...")`) | ✅ |
| Subdomain enum (crt.sh + DNS dictionary + subfinder/httpx CLI) | ✅ |
| Content discovery (250-path built-in + ffuf CLI) | ✅ |
| Tech / CMS fingerprint | ✅ |
| Port scanning (built-in + nmap + naabu + masscan) | ✅ |
| **WAF detection / fingerprint** (Cloudflare, Akamai, Incapsula, AWS WAF, Sucuri, F5) | ❌ |
| **Wayback / archive.org URL recovery** | ❌ |
| **Cloud bucket name guessing** (S3 / Azure blob / GCS) | ❌ |
| **Service worker / PWA inventory** | ❌ |
| **WebSocket discovery + handshake test** | ❌ |
| **JS bundle AST analysis** (extract API URLs + identifiers from minified) | 🟡 regex-only |

## 2. Passive analysis

| Method | Status |
|---|---|
| Security headers (per-URL coverage) | ✅ |
| Cookie posture (Secure/HttpOnly/SameSite/Domain/MaxAge) | ✅ |
| TLS handshake (basic + testssl.sh CLI) | ✅ |
| CORS misconfiguration (5 vectors) | ✅ |
| JWT structural analysis | ✅ |
| GraphQL introspection probe | ✅ |
| SRI / supply-chain audit | ✅ |
| Tech / framework / CDN fingerprint | ✅ |
| **CSP bypassability analyzer** (JSONP allow-list, AngularJS gadgets in source) | 🟡 keyword-only |
| **Email spoofing** (SPF / DKIM / DMARC via DNS) | ❌ |
| **HSTS preload list lookup** | ❌ |
| **DNS records audit** (CAA / wildcard / dangling CNAME) | ❌ |
| **Source map exposure** (`*.js.map` reachable) | ❌ |
| **Internal IP / debug-page leakage** (Symfony `/_profiler`, Django debug, Express `?debug=`) | 🟡 partial via content-discovery |
| **HTML comments disclosure** | ❌ |

## 3. Active injection (server-side)

| Method | Status |
|---|---|
| Reflected XSS (HTML + JSON-aware) | ✅ |
| Stored XSS submit | ✅ form-fuzzer |
| **Stored XSS persistence confirmation** (re-fetch + match) | ❌ |
| **Blind XSS (OOB)** | ❌ needs callback |
| **DOM-based XSS** (headless Chrome) | ❌ roadmap |
| **SQL injection** — 5 DBMS × 4 techniques × 5 injection-point types | ✅ `web.sqli` |
| LFI / path traversal | ✅ |
| OS command injection | ✅ |
| SSRF (AWS IMDS canary) | ✅ |
| **SSRF — Azure / GCP metadata variants** | ❌ |
| **SSRF — IMDSv2 token request** | ❌ |
| Open redirect | ✅ |
| SSTI (Jinja2/Twig/Velocity/Razor/ERB/Smarty/Freemarker) | ✅ |
| NoSQL injection (Mongo `$ne`/`$gt`/`$regex`) | ✅ |
| XXE (local-file) | ✅ |
| **XXE (out-of-band)** | ❌ needs callback |
| Prototype pollution | ✅ |
| CRLF / response splitting | ✅ |
| Host header / Forwarded injection | ✅ |
| HTTP request smuggling (CL.TE basic) | ✅ basic |
| Mass assignment | ✅ |
| Race condition (parallel-POST) | ✅ |
| Verb tampering / method override (7 vectors) | ✅ |
| IDOR (sequential id pivot) | ✅ |
| Hidden parameter mining | ✅ |
| **LDAP injection** | ❌ |
| **XPath injection** | ❌ |
| **SSI (Server-Side Includes) injection** | ❌ |
| **ESI (Edge-Side Includes) injection** | ❌ |
| **JSONP callback injection** | ❌ |
| **HTTP Parameter Pollution (HPP)** | ❌ |
| **Cache poisoning** (X-Forwarded-Host / X-Original-URL / Vary games) | ❌ |
| **Cache deception** (`/profile/data.css` returns user data) | ❌ |
| **GraphQL field-level fuzzer** (BOLA per type, batching DoS, depth bomb) | ❌ — only introspection check |
| **WebSocket frame fuzzing** | ❌ |
| **Range header DoS / billion-requests / HTTP/2 RST flood** | ❌ |
| **HTTP/2 / HTTP/3 specific attacks** (h2c smuggling, :authority CRLF) | ❌ |
| **WebDAV verb tampering** (PROPFIND / MKCOL / COPY) | ❌ |

## 4. Authentication

| Method | Status |
|---|---|
| Default credential brute (login forms) | ✅ |
| JWT alg=none / empty-sig / no-exp / kid traversal / PII | ✅ |
| Session cookie posture | ✅ |
| **JWT HS256 secret cracking** (common-secrets dictionary) | ❌ |
| **Session fixation** (login + cookie unchanged) | ❌ |
| **Logout doesn't invalidate session** | ❌ |
| **Username enumeration** (login error timing/content diff) | ❌ |
| **Password reset token guessability** | 🟡 host-header injection covers part |
| **2FA absence / weak OTP brute** | ❌ |
| **OAuth / OIDC redirect_uri bypass** | ❌ |
| **OAuth state-param missing** | ❌ |
| **SAML signature wrap (XSW)** | ❌ |
| **JWKS endpoint abuse / kid alg confusion** | ❌ |
| **Remember-me cookie analysis** | ❌ |
| **Rate-limit absence on login / password-reset / 2FA** | 🟡 partial via brute-login |
| **Password policy weakness** (registration accepts `1`) | ❌ |
| **CAPTCHA bypass** detection | ❌ |

## 5. Authorization (Broken Access Control)

| Method | Status |
|---|---|
| Verb tampering bypass | ✅ |
| IDOR sequential-id | ✅ |
| **Force browsing low-priv → high-priv** | ❌ |
| **JWT role tampering** (decode → re-sign) | ❌ |
| **Impersonation header tests** (X-Original-User, X-User-Id) | ❌ |
| **GraphQL field-level auth check** (call User.email on someone else's id) | ❌ |
| **API key in URL detection** | ❌ |
| **HTTP Basic / Bearer in querystring** | ❌ |

## 6. File handling

| Method | Status |
|---|---|
| **File upload extension bypass** (`.php.jpg`, `.php5`, polyglot) | ❌ |
| **Image upload SVG XSS / SSRF** | ❌ |
| **ZIP slip** | ❌ |
| **Polyglot file detection** | ❌ |
| **EXIF / metadata leak** | ❌ |
| **Range header file disclosure** | ❌ |

## 7. Business logic

| Method | Status |
|---|---|
| Race condition (parallel POST) | ✅ |
| **Workflow bypass** (skip step) | ❌ |
| **Unit price tampering** (negative qty, 0 amount) | ❌ |
| **Coupon / promo abuse** | ❌ |
| **Replay attacks** (resubmit signed request) | ❌ |
| **Numeric overflow / underflow** | ❌ |

## 8. Information disclosure

| Method | Status |
|---|---|
| Sensitive paths (.env / .git / .DS_Store / actuator / server-status / xmlrpc) | ✅ |
| Server / X-Powered-By version | ✅ |
| GraphQL introspection | ✅ |
| **Source map (`*.js.map`) exposure** | ❌ |
| **Stack trace fingerprinting** (Django debug, Symfony, Rails dev) | 🟡 partial via content-discovery |
| **Backup file extension probes** (`.bak`, `.swp`, `.orig`, `~`) | 🟡 partial |
| **SSL cert SAN over-disclosure** | ❌ |

## 9. Known CVEs / 0-days

| Method | Status |
|---|---|
| Built-in CVE pack (~24 high-impact) | ✅ `web.cve-pack` |
| Nuclei integration (~8000 templates) | ✅ CLI adapter |
| **Recent zero-days** | ❌ inherently — install nuclei + auto-update templates |

## 10. Deserialization

| Method | Status |
|---|---|
| XXE | ✅ |
| **Java serialized object** (magic bytes `AC ED 00 05`) | ❌ |
| **PHP `unserialize` (`O:N:...`)** | ❌ |
| **Python pickle** | ❌ |
| **.NET BinaryFormatter** | ❌ |
| **Ruby YAML / Marshal** | ❌ |

## 11. Cloud / Infrastructure

| Method | Status |
|---|---|
| AWS IMDS probe | ✅ basic |
| **AWS IMDSv2 token request** | ❌ |
| **Azure metadata** (`/metadata/instance`) | ❌ |
| **GCP metadata** | ❌ |
| **Kubernetes API** (`/api/v1` exposed) | ❌ |
| **Docker socket** (TCP 2375) | 🟡 port scan only |
| **etcd open** (port 2379) | 🟡 port scan only |
| **Prowler / Scout Suite (AWS audit)** | ❌ |
| **kube-bench / kube-hunter** | ❌ |

## 12. Source / SAST

| Method | Status |
|---|---|
| Regex secrets (built-in) | ✅ |
| Multi-language SAST (semgrep, codeql, bandit, brakeman, eslint-security) | ✅ via CLI |
| Dep CVEs (trivy, osv-scanner, snyk, dependency-track) | ✅ |
| Secret-history sweep (gitleaks, trufflehog, detect-secrets) | ✅ |
| IaC misconfig (checkov, trivy IaC) | ✅ |
| **Lockfile-lint** (npm/yarn/pnpm) | ❌ |
| **`pip-audit` / `safety`** (Python) | 🟡 osv covers most |
| **`cargo-audit` / `govulncheck`** | 🟡 osv covers most |
| **`composer audit`** (PHP) | 🟡 osv |
| **License policy enforcement** | ❌ — info only |
| **Reachability analysis** (is the vulnerable code path called?) | ❌ |
| **PR-diff scanning mode** | ❌ |
| **Code complexity / hotspot** | ❌ |
| **Binary analysis (Ghidra-style)** | ❌ |

## 13. Mobile / IoT

| Method | Status |
|---|---|
| **APK static analysis (MobSF)** | ❌ |
| **iOS IPA analysis** | ❌ |
| **Firmware extraction** | ❌ |

## 14. Operational

| Method | Status |
|---|---|
| Realtime SSE UI streaming | ✅ |
| SARIF 2.1.0 export | ✅ |
| LLM triage (Claude) | ✅ |
| Chain detection (composite findings) | ✅ |
| Parallel scanner execution | ✅ |
| Finding deduplication | ✅ |
| **HAR import** | ❌ |
| **OpenAPI / Postman / Swagger import** | ❌ |
| **Authenticated session (Playwright login recorder)** | ❌ |
| **Shared user+bot browser session** | ❌ |
| **MITM proxy mode** | ❌ |
| **Diff baseline / regression** | ❌ |
| **CI/CD GitHub Action** | ❌ |
| **Scheduled scans / cron** | ❌ |
| **Slack / JIRA / Linear webhooks** | ❌ |
| **Multi-tenant / RBAC** | ❌ |

## Honest score (web DAST)

|  | Count |
|---|---|
| ✅ Shipped | ~95 distinct methods |
| 🟡 Partial / via CLI / heuristic-only | ~10 |
| ❌ Missing | ~60 |

**~58% method-coverage** of a full pentest playbook. Most of the missing
ones split into three buckets:

1. **Need OOB callback service** (interact.sh / Burp Collaborator) — blind RCE,
   blind SSRF, blind XSS, OOB XXE. Easiest path: wrap interactsh-client.
2. **Need a headless browser** — DOM XSS, AngularJS sandbox escape, service
   worker probe, JS-rendered SPA crawl. Easiest path: wrap Playwright.
3. **Pure-built — just haven't been written yet** — WAF detection, source-map
   exposure, HPP, cache poisoning, email auth records, JWT secret cracking,
   username enum, LDAP/XPath/SSI/ESI injection, OAuth abuse, JSONP, K8s/Azure/GCP
   metadata, deserialization probes, file-upload abuse, business-logic.
   These are what we ship next.

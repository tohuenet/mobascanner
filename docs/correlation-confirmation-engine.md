# Brief: Correlation & Confirmation Engine (moba-scanner's anti-Acunetix wedge)

> **Người dùng (VI):** Đây là design brief để bàn giao cho Opus/Sonnet 5 (giống `docs/dashboard-report-optimization.md`). Nó xây **con hào cạnh tranh** của sản phẩm: tương quan & xác nhận chéo giữa DAST (web) và SAST/SCA (source) — thứ mà một công cụ DAST-only đóng như Acunetix về cấu trúc không làm được. Toàn bộ đã được kiểm chứng trực tiếp trong code (có trích dẫn file:line). Đọc từ đây bằng tiếng Anh để khớp codebase.

---

## 0. The insight this is built on (verified in code)

The competitive wedge is **cross-surface correlation + confirmation**: a finding is far more valuable when the *source* side (SAST/SCA) and the *running* side (DAST) agree on it. moba owns both sides; Acunetix (DAST-only) and SonarQube/Snyk (source-only) structurally cannot join them.

**The machinery mostly exists — but it is currently *latent and unreachable*.** Verified:

- A `Scan` is **single-kind** (`ScanKind = "web" | "source"`, `lib/types.ts`). The runner filters scanners to the scan's kind: `.filter((s) => s.kind === scan.kind)` (`lib/engine/runner.ts:68`). **Therefore web findings and source findings never co-exist in one scan.**
- `detectChains(scanId, findings)` (`lib/triage/chains.ts`) already contains **cross-kind chain rules** — `chain/cve-plus-secret` (dep CVEs + source secrets) and `chain/db-port-plus-env` (web port + leaked env). But it runs post-scan over **one scan's** findings only (`lib/engine/runner.ts:248-261`), so **those cross-surface rules can never fire today.** They are dead code waiting for a union input.
- There is **no "project"/asset-group entity** linking a web scan of `app.example.com` to a source scan of its repo. No cross-scan analysis exists.

So this feature is mostly **connecting siloed pieces**, not building from scratch. That is the opportunity.

## 1. What's already real (reuse it — verified)

| Capability | File | Reuse as |
|---|---|---|
| Chain detection (7 rules, incl. cross-kind) | `lib/triage/chains.ts` (`detectChains`) | Feed it the **union** of a project's findings → latent rules fire |
| ROI ranker | `lib/triage/ranker.ts` (`rankFindings`) | Rank correlated findings to the top |
| LLM triage (is_real / severity / narrative / remediation) | `lib/triage/llm.ts` (`triageFindings`, `mergeTriage`) | **Confirmer** for ambiguous joins; needs `ANTHROPIC_API_KEY` |
| Agentic live-probe loop (safe, sandboxed) | `lib/triage/agentic.ts` (`runAgenticLoop`) | **Active confirmation** of a specific cross-surface hypothesis |
| Dedup | `lib/engine/dedup.ts` (`dedupFindings`) | Dedupe correlated output |
| Store (per-scan JSONL + `data/index.json`) | `lib/store.ts` | Extend with a `projects` sibling (same simple-JSON pattern, no DB) |

## 2. Join keys that actually exist today (verified — this determines what's buildable now vs. later)

- **CVE id (STRONG, available now).** `Finding.cve: string[]`. Source: trivy emits `cve: [VulnerabilityID]` + `evidence: { pkg, installed, fixed }` (`lib/scanners/source/trivy.ts:118-134`). Web: `web.cve-pack` emits `cve: [probe.cve]` for ~25 high-impact CVEs (`lib/scanners/web/cve-pack.ts`), and nuclei findings carry CVE ids too. → **Joining on a shared CVE id across a web finding and a source finding is possible with today's data.** This is the MVP join.
- **Package + version (PARTIAL — needs one enhancement).** Source has structured `pkg@installed` (trivy evidence). But **`web.fingerprint` detects stack *names* only, not versions** (`lib/scanners/web/fingerprint.ts:86-108` builds `{name, via}` — no version parsing). So "is this vulnerable package actually served live?" needs a **fingerprint/live-SBOM enhancement** (Phase 2), not available today.
- **URL / route ↔ file:line (HARD).** Findings carry `location.url` (web) and `location.file:line` (source) but **no route mapping** links a controller file to a live URL. Framework-specific. Phase 3+.
- **Secrets (available, but confirmation is dangerous).** Source secret findings exist (trivy/gitleaks/regex-secrets). "Confirming" a leaked secret by live authentication is destructive/risky → **opt-in only, default off.**

## 3. Hard constraints (same as the UI brief — READ FIRST)

1. **Next.js 16.2.6 has breaking changes.** Before writing any route handler / page / `metadata`, read the relevant guide under `node_modules/next/dist/docs/` (root `AGENTS.md`). Async params; typed `RouteContext`/`PageProps`; `export const runtime = "nodejs"` + `export const dynamic = "force-dynamic"` on dynamic routes.
2. **No new npm dependencies** without justification. `zod` (already present) for schema validation of new API bodies is fine.
3. **Reuse the domain model** in `lib/types.ts`. Do not fork `Finding`/`Scan`. Correlated findings are `Finding` objects synthesized the same way chain findings are (`lib/triage/chains.ts:198-225`): `scannerId: "correlation"`, `evidence.contributingFindings: string[]`, `evidence.crossSurface: true`. If a first-class link is needed, add ONE optional field `Finding.correlation?: { scanIds: string[]; join: "cve" | "chain" | "version"; contributes: string[] }` — optional so nothing else breaks.
4. **Persistence follows the existing pattern.** JSON files, no database. Add `data/projects/<id>/project.json` (+ `findings.jsonl` for correlated output). Mirror `lib/store.ts` helpers.
5. **Correlation must be idempotent + re-runnable.** Dedupe by the sorted set of contributing finding ids; re-running after a new member scan updates, never duplicates.
6. **Safety:** never auto-attempt live auth with leaked secrets; never auto-link projects without user confirmation (false domain↔repo matches are worse than manual). Agentic/LLM confirmation only when `ANTHROPIC_API_KEY` is set, and must degrade gracefully when it isn't.
7. **Don't block on the UI work.** The engine core (Phases 0–1) lives in `lib/` + new `app/api/projects/*` routes + one standalone page — disjoint from the dashboard/report UI phases. But the *surfacing* (Phase 4) depends on the report UI; sequence it after.

## Phase 0 — Project entity + linking (foundation)

- **Model:** `Project { id; name; createdAt; targets: { host?: string; repo?: string }; members: { scanId: string; kind: ScanKind; target: string; addedAt: number }[]; meta? }`.
- **Store** (`lib/store.ts` or new `lib/projects/store.ts`): `createProject`, `getProject`, `listProjects`, `addScanToProject(projectId, scanId)`, `removeScanFromProject`, `deleteProject`. Add a `data/projects/index.json` list mirroring `data/index.json`.
- **API** (read Next 16 route docs first): `GET/POST /api/projects`, `GET/PATCH/DELETE /api/projects/[id]`, `POST /api/projects/[id]/scans` (attach a scan), `POST /api/projects/[id]/correlate` (run the pass).
- **Linking UX:** from a completed scan's overflow menu, "Add to project…" (pick existing or create). Optional **auto-suggest**: when creating, if a web target host and a source repo name share a token (`foo.com` ↔ `github.com/acme/foo`), suggest grouping — **low-confidence, user must confirm.** Manual is the reliable path.
- *Acceptance:* a user can create a project, attach one web scan + one source scan of the same app, and see both listed as members.

## Phase 1 — MVP correlation (works with TODAY's data)

Implement `lib/correlation/engine.ts` exporting `correlateProject(projectId): Promise<Finding[]>`:

1. **Load the union** of all member scans' findings (`listFindings` per member).
2. **CVE-id cross-surface join (the headline):** normalize CVE ids (upper-case, `CVE-YYYY-N`), group findings by CVE id, and for any CVE present in **both** a `web`-origin finding **and** a `source`-origin finding, synthesize a correlated `Finding`:
   - title e.g. `Confirmed cross-surface: {CVE} present in dependency AND live on the running app`
   - description joins both sides: `pkg@version` from the source finding's `evidence.pkg/installed`, and the live URL from the web finding's `location.url`.
   - `severity` = max of contributors (consider +1 escalation since it's cross-validated), `confidence: "high"`, `evidence.contributingFindings = [webId, sourceId]`, `evidence.crossSurface = true`, `cve`, `cwe`, `owasp` merged.
3. **Run existing chains over the union:** call `detectChains(projectId, unionFindings)` so the latent cross-kind rules (`chain/cve-plus-secret`, `chain/db-port-plus-env`) finally fire. (This alone is a visible win.)
4. **Optional LLM confirmation:** if `ANTHROPIC_API_KEY` set, pass borderline joins through `triageFindings` for is_real/severity/narrative; attach to evidence. Skip cleanly when absent.
5. **Persist** to `data/projects/<id>/findings.jsonl` (idempotent dedupe by contributing-id set); expose via `GET /api/projects/[id]/findings`.
- *Acceptance:* scan a Log4j-style app on the web side **and** its repo on the source side (both surface CVE-2021-44228), attach both to a project, correlate → exactly one `critical` correlated finding referencing both contributing findings; re-running does not duplicate it.

## Phase 2 — Reachability-lite (the bigger FP-cutting win; needs one enhancement)

- **Enhance `web.fingerprint`** (or add `web.live-sbom`) to extract **live library versions** — from `Server` / `X-Powered-By` headers, `<meta name="generator">`, Next.js `/_next/` build manifest, common JS bundle version markers, exposed `/package.json`, favicon/asset hashes. Emit structured `evidence: { pkg, version, source: "header|meta|bundle" }`.
- **Correlation gains a version join:** SCA `pkg@installed` (source) ↔ live `pkg@version` (web). When a vulnerable dependency is **observed live**, escalate ("shipped to production"); when a repo CVE's package is **not** observed live, mark `not-observed-at-runtime` and **deprioritize** — this is the concrete false-positive-cutting story that beats Acunetix's noise.
- *Acceptance:* an SCA CVE for a package served live is escalated + labeled "confirmed live"; the same class of CVE for a build-only/dev dependency not served live is deprioritized with a clear reason.

## Phase 3 — Route-level SAST↔DAST join (hardest; framework-scoped, NON-goal for MVP)

Map source route handlers → live URLs (Express/Next/Spring/Rails, one framework at a time) and join SAST injection findings (file:line + inferred route) with DAST-confirmed injection at the same route/param. Explicitly iterative research; do **not** attempt in the MVP. Document it as the roadmap tail.

## Phase 4 — Surface it in the product (depends on the UI phases)

- A **Projects** section (list + detail) whose report leads with **Correlated / Confirmed** findings (a distinct "Confirmed cross-surface" badge), reusing the report components from `docs/dashboard-report-optimization.md`.
- Extend the report exporter (`app/api/scans/[id]/report/route.ts` → a project variant) with a "Cross-surface confirmed" section.
- Add the "Projects" nav entry in `AppShell` **as part of the UI consistency phase**, not here, to avoid nav-file conflicts.
- *Acceptance:* the project report answers "what did both the code and the running app agree is exploitable?" above everything else.

## 4. Non-goals / honesty (state these; don't overpromise)

- **Not** full static call-graph reachability — that's a multi-month research effort. We do **evidence-join reachability** (CVE-id match, live-version match), which is achievable and honest.
- **No** auto-linking of web↔source without user confirmation.
- **No** live exploitation of leaked secrets; secret "confirmation" stays opt-in and non-destructive.
- LLM/agentic confirmation is an **enhancer**, never a hard dependency — the CVE-id join and chains work with zero API key.

## 5. Definition of done (per phase)

- Phase 0–1: `pnpm exec tsc --noEmit`, `pnpm run lint`, `pnpm run build` all clean; correlation is idempotent; CVE-id join + cross-kind chains verified against a real two-scan project; graceful with no `ANTHROPIC_API_KEY`.
- No new deps (or justified). No secrets rendered. New routes follow Next 16 conventions (docs read first).
- Every synthesized finding carries `contributingFindings` so the UI can show provenance.

## 6. How to verify

1. `pnpm run dev`. Create two scans of the same app: a **web** scan of a target that trips `web.cve-pack` (e.g. a Log4Shell/Struts test app or `demo.testfire.net`) and a **source** scan of a repo whose deps trivy flags with the same CVE.
2. Create a project, attach both, `POST /api/projects/[id]/correlate`.
3. Confirm exactly one correlated `critical` finding per shared CVE, referencing both contributors; re-run → no duplicates; unset `ANTHROPIC_API_KEY` → still works (LLM step skipped).
4. Check a cross-kind chain fires on a project that has both a dep CVE and a source secret (`chain/cve-plus-secret`) — impossible before this feature.

## 7. Suggested sequencing

The dashboard/report UI phases (`docs/dashboard-report-optimization.md`) are in flight. Recommended order: **UI Phases 1–3 → this engine Phase 0–1 → this Phase 2 → surface (Phase 4) → route-level (Phase 3, ongoing).** The engine core (0–1) is `lib/` + `app/api/projects/*` + one standalone page, so it *can* start in parallel with the UI work if desired — just keep it out of `AppShell`/`globals.css`/report files until the UI phases land.

---

### Appendix — exact anchors

- Single-kind filter: `lib/engine/runner.ts:68` (`.filter((s) => s.kind === scan.kind)`).
- Chain pass location: `lib/engine/runner.ts:248-261`; rules: `lib/triage/chains.ts` (`RULES`, `detectChains`).
- Latent cross-kind rules: `chain/cve-plus-secret` (`chains.ts:110-127`), `chain/db-port-plus-env` (`chains.ts:130-153`).
- Source SCA join data: `lib/scanners/source/trivy.ts:118-134` (`cve`, `evidence.pkg/installed/fixed`).
- Web CVE join data: `lib/scanners/web/cve-pack.ts` (`cve: [probe.cve]`, `ruleId: cve/…`).
- Fingerprint has NO version extraction: `lib/scanners/web/fingerprint.ts:86-108`.
- LLM confirmer: `lib/triage/llm.ts` (`triageFindings`, `mergeTriage`); agentic: `lib/triage/agentic.ts` (`runAgenticLoop`).
- Store pattern to mirror: `lib/store.ts` (`createScan`/`getScan`/`listScans`/`data/index.json`).
- Finding synthesis pattern to copy: `lib/triage/chains.ts:198-225`.

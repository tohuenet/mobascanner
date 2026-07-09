# Brief: Tối ưu luồng chính — Dashboard & Trang báo cáo (moba-scanner)

> **Dành cho người dùng (VI):** Đây là bản đặc tả công việc (work brief / prompt) để bàn giao cho **Claude Opus / Sonnet 5** chạy trong Claude Code. Mục tiêu: nâng chất lượng **luồng chính** của sản phẩm — *Dashboard (Overview)* và *Trang báo cáo kết quả scan* — rồi sửa những phần liên quan cần thiết. Cách dùng: mở một phiên Claude Code mới trong repo này, dán nội dung file `docs/dashboard-report-optimization.md` làm prompt, hoặc chỉ cần nói *"Đọc `docs/dashboard-report-optimization.md` và thực hiện Phase 1 → 3"*. Brief cố ý viết bằng tiếng Anh từ đây trở xuống để khớp ngôn ngữ codebase và để agent code chính xác.

---

## 0. Mission

You are improving the **main flow** of `moba-scanner`, a self-hosted web + source security console (Acunetix-style DAST + SonarQube-style SAST/SCA, wrapping open-source tools under one UI). The main flow is:

```
Overview (dashboard)  →  Start scan  →  Scan detail (live report)  →  Export / share
   app/page.tsx           app/scan/*       app/scans/[id]/*            /api/scans/[id]/report
```

Two surfaces are the priority: the **Dashboard** (`app/page.tsx`) and the **Report / scan-detail page** (`app/scans/[id]/…`). After those, make the *necessary* supporting changes so the flow feels coherent (Phase 3). The overriding goal is **product quality**: clarity of information, a "results-first" report, correctness of the numbers shown, accessibility, and light/dark polish — not decoration for its own sake.

Work in phases. Read this whole brief first, then read the code you're touching before editing it.

---

## 1. Hard constraints — READ BEFORE WRITING CODE

1. **This is NOT the Next.js you know.** The repo pins **Next.js 16.2.6** with breaking changes vs. training data (see root `AGENTS.md`). Before writing any Next-specific code (routing, `metadata`, server/client boundaries, route handlers, `<Link>`, `<Image>`, caching, `params`), **read the relevant guide under `node_modules/next/dist/docs/`** and heed deprecation notices. Do not assume APIs from memory.
   - Observed conventions in this repo you must preserve: pages are async Server Components; dynamic pages set `export const dynamic = "force-dynamic"`; route params are **async** (`const { id } = await props.params`); typed route helpers are used (`PageProps<"/scans/[id]">`, `RouteContext<"/api/scans/[id]/report">`). Route handlers set `export const runtime = "nodejs"`.
2. **React 19.2** — Server Components by default. Only add `"use client"` when you need state/effects/DOM. Keep long-lived state (SSE listeners, reducers) at the page level, not inside tabs (the codebase already does this — follow it).
3. **Styling = Tailwind v4 + design tokens only.** No new UI/component/animation libraries, no CSS-in-JS runtime. Use the existing tokens and utilities in `app/globals.css` and the primitives in `components/ui/Primitives.tsx`. If you need a new token, add it to `globals.css` for **both** light `:root` and the dark `@media (prefers-color-scheme: dark)` block.
4. **No new npm dependencies** unless there is no reasonable alternative — and if so, call it out and justify it in the PR description before adding.
5. **Keep the server/client data contract intact.** Data comes from `lib/store.ts` (`listScans`, `getScan`, `listFindings`) and live updates from SSE `/api/scans/[id]/stream`. Types live in `lib/types.ts` — reuse `Finding`, `Scan`, `Severity`, `SEVERITY_RANK`, `EMPTY_COUNTS`; do not invent parallel shapes.
6. **Accessibility is part of "done."** Every interactive element must be keyboard-reachable with a visible focus ring (the global `:focus-visible` ring already exists), have an accessible name, and never rely on color alone to convey severity (pair color with text/label). Respect `prefers-reduced-motion` (already honored by `.glass*` blur fallback — keep new animations behind it).
7. **Don't regress the existing "results-first" architecture** of the scan-detail page (documented in `app/scans/[id]/ScanDetailClient.tsx`): header → the answer (severity counters) → tabs for process detail. Enhance it; don't flatten it back into a wall of process logs.

---

## 2. Design language (recap so you match it exactly)

- **Material 3 + "Liquid Glass."** Surfaces use `.glass` / `.glass-strong` / `.glass-thin` (translucent, blurred, edge-highlighted). Cards, menus, tiles are glass. See `app/globals.css` lines for the exact recipes.
- **Color:** everything references CSS vars — `--md-primary`, `--md-secondary`, `--md-tertiary`, `--md-error`, surface/`on-surface` families, `--md-outline(-variant)`, and severity ramp `--md-severity-{critical,high,medium,low,info}`. Never hard-code hex; use `var(--…)` and `color-mix(in oklab, …)`.
- **Typography:** the `md-display-*` / `md-headline-*` / `md-title-*` / `md-body-*` / `md-label-*` utility classes. Use them instead of ad-hoc `text-xl` etc.
- **Shape/state:** radius tokens `--md-shape-*`; the `.state-layer` utility supplies M3 hover/press overlays — add it to new clickable surfaces.
- **Primitives available:** `Button` (filled/tonal/outlined/text/elevated), `Card`, `Chip`, `SeverityBadge`, `ProgressBar`, `TextField`, `Switch`, `Skeleton`. Prefer composing these over raw elements. If you find yourself duplicating a pattern 3×, promote it to a primitive.

---

## 3. Product principles for this work

1. **Show the truth, precisely.** A headline number must mean exactly what it says. If a metric covers "last 8 scans," the label must say so — or compute it over the real population.
2. **Answer first, evidence second.** Overview should answer "what's my security posture right now?" in the first screen. The report should answer "what did we find and what do I fix first?" before any process detail.
3. **Every finding is actionable.** Severity, location, remediation, references, and (if present) triage state should be legible and, where possible, one click from an action.
4. **Consistency beats novelty.** Reuse the same severity chips, the same empty-state pattern, the same glass tiers across pages. Divergence between the dashboard and the scans list (they currently render severity differently) is a bug, not a style choice.
5. **Graceful at every state:** empty (no scans yet), running (live), completed, failed, cancelled. Design each explicitly.

---

## 4. Current main-flow file map

| Surface | Files |
|---|---|
| Dashboard | `app/page.tsx` |
| App chrome / nav | `components/AppShell.tsx`, `app/layout.tsx` |
| Start web scan | `app/scan/web/page.tsx`, `components/ScannerSelector.tsx`, `components/auth/*` |
| Start source scan | `app/scan/source/page.tsx` |
| Scans history | `app/scans/page.tsx` |
| **Report / scan detail** | `app/scans/[id]/page.tsx` → `components/*`: `ScanHeader.tsx`, `SeverityCounters.tsx`, `scan-tabs/Tabs.tsx`, `scan-tabs/FindingsTab.tsx` → `FindingsList.tsx`, `scan-tabs/SiteMapTab.tsx`, `scan-tabs/ActivityTab.tsx`, `scan-tabs/LogsTab.tsx`. Client orchestrator: `app/scans/[id]/ScanDetailClient.tsx` |
| Export | `app/api/scans/[id]/report/route.ts` (markdown / exec-summary), `app/api/scans/[id]/sarif/route.ts` |
| Design system | `app/globals.css`, `components/ui/Primitives.tsx` |
| Data | `lib/store.ts`, `lib/types.ts`; ranking used by report export: `lib/triage/ranker.ts` (`rankFindings`) |

---

## 5. Confirmed defects to fix (evidence-based — verify, then fix)

- **D1 — Dashboard "posture" number is misleading.** `app/page.tsx` computes `totalCounts` from `scans.slice(0, 8)` (only the 8 most recent), then displays it as the hero's headline severity totals with no qualifier. Either (a) compute the aggregate across **all** scans from the index (`listScans()` returns counts for every scan), or (b) label the tile explicitly as "last 8 scans." Prefer (a) for the top KPI and keep a separate "recent" list. Decide and make the label honest.
- **D2 — "Export HTML report" exports Markdown.** In `components/ScanHeader.tsx` the overflow menu item **"Export HTML report"** links to `/api/scans/[id]/report`, but `app/api/scans/[id]/report/route.ts` returns `text/markdown` with filename `moba-<id>.md`. Also, the route supports `?format=exec-summary` that the UI never surfaces. Fix the mismatch: either add a real self-contained HTML report route (preferred — see Task R6) and point the menu at it, or relabel the item to "Export Markdown report." Additionally expose the exec-summary format somewhere.
- **D3 — Dashboard vs. scans-list severity rendering diverge.** `app/scans/page.tsx` renders per-severity via `SeverityBadge` and **hides zero counts**; `app/page.tsx` renders all five severities inline **including zeros**. Unify on one treatment (dim/hide zeros).
- **D4 — No mobile navigation.** `components/AppShell.tsx` hides the sidebar `hidden md:flex` and the mobile header shows only brand + status — there is **no way to navigate between sections on mobile**. This breaks the main flow on phones. Add a mobile nav (top drawer or bottom bar). (Phase 3.)

---

## Phase 1 — Dashboard (`app/page.tsx`) — PRIORITY

Goal: turn the overview from a static welcome into a **security-posture cockpit** that answers "where do I stand and what needs attention," while keeping the calm M3/glass aesthetic.

**T1.1 [P0] Correct, meaningful KPI row.** Replace/augment the hero's five raw counters with a small set of *true* KPIs computed over all scans (`listScans()`):
- Open **Critical + High** (the "act now" number), with the same severity color language.
- Total scans and total findings (all-time).
- Targets scanned (distinct `target`).
- Last scan time + status.
Fix D1 as part of this. Keep the 5-severity breakdown but label its scope honestly.
- *Acceptance:* every number matches a hand-computed value from `data/index.json`; each KPI has a text label; no unlabeled aggregate.

**T1.2 [P1] Surface active scans.** If any scan is `running`/`queued`, show a compact "In progress" strip at the top (target + a `ProgressBar`, indeterminate if unknown), linking to its report. This is server-rendered from `listScans()`; a live progress bar is a bonus (can poll or leave indeterminate).
- *Acceptance:* starting a scan then visiting `/` shows it as active with a link; when none are active the strip is absent (not an empty box).

**T1.3 [P1] Recent scans: cleaner, denser, consistent.** Reuse the scans-list row treatment (via `SeverityBadge`, zeros hidden) so `/` and `/scans` look like one product (fixes D3). Show target, kind, status, relative time (e.g. "3m ago"), and non-zero severities. Make the whole row a `state-layer` link (already is).
- *Acceptance:* dashboard rows and `/scans` rows are visually consistent; zero-severity noise gone.

**T1.4 [P2] Make the scanner inventory actionable.** The inventory currently reads like static copy. Show live availability by reading `/api/tools` (or `listScanners()` + `.tool()`): a "ready / not installed" chip per scanner and a count like "12/18 scanners ready," with a link to `/tools`. If wiring live status is heavy, at minimum link each card to `/tools` and group by `kind` (web/source).
- *Acceptance:* a user can tell at a glance how many scanners are installed and reach the install page in one click.

**T1.5 [P2] First-run / empty state.** When there are no scans, replace the one-liner with a proper onboarding card: two primary CTAs (Web / Source), a one-line "authorized testing only" reminder, and the quick-target hint. Keep it warm, not empty.

**T1.6 [P2] Perceived performance.** Add an `app/loading.tsx` (or Suspense boundaries) with `Skeleton` tiles so the force-dynamic dashboard doesn't flash blank on slow data reads.

---

## Phase 2 — Report / scan-detail — PRIORITY

Goal: make the scan-detail page a **credible security report** — skimmable by a manager, actionable by an engineer — without losing the live/streaming experience. Touch: `ScanDetailClient.tsx`, `SeverityCounters.tsx`, `ScanHeader.tsx`, `FindingsList.tsx`, `scan-tabs/*`, and the export route.

**T2.1 [P0] Add a "Summary / Overview" as the report's landing.** Above or as the first tab, add a concise result summary that reuses `lib/triage/ranker.ts`:
- A **Top findings by ROI** list (the `rankFindings` output that today is only visible in the Markdown export) — 3–5 items, each linking to the finding in the Findings tab.
- Rollups: findings by scanner, and by OWASP/CWE if present on the findings.
- Top affected locations (URLs for web, files for source) by count.
Keep it compact and glass-carded. This is the single biggest quality lift on the report.
- *Acceptance:* opening a completed scan answers "what should I fix first?" without scrolling into the raw list.

**T2.2 [P0] Make severity counters interactive + add a total.** In `SeverityCounters.tsx`, clicking a tile deep-links to the Findings tab pre-filtered to that severity (drive it through the existing `?tab=` URL sync in `Tabs.tsx` plus a severity query param that `FindingsList` reads). Add a sixth "Total" tile. Keep them keyboard-operable (`button`/`role`, focus ring) — they are currently inert `div`s.
- *Acceptance:* clicking "High" lands on Findings filtered to High; keyboard Enter/Space works; screen reader announces the control.

**T2.3 [P1] Upgrade the findings list.** In `FindingsList.tsx`:
- Show **per-severity counts** on the filter chips (e.g. "high 4"), and dim severities with zero results.
- Add a **sort** control (severity — current default; also CVSS; confidence; scanner; newest).
- Add optional **group-by** (scanner / severity / affected location) with collapsible groups; default ungrouped.
- Add a **triage-state filter** (the model has `Finding.triage.state`: open / false-positive / fixed / accepted-risk). Hide/segregate non-open findings behind the filter.
- Preserve current search behavior.
- *Acceptance:* a 100-finding scan is navigable — filter by severity+scanner, sort by CVSS, and find a specific URL quickly.

**T2.4 [P1] Per-finding actions.** On each `FindingCard`:
- **Copy link** to this specific finding (assign stable anchors, e.g. `#f-<id>`, and open the card + scroll on load when the hash matches).
- **Copy as Markdown** (title, severity, location, description, remediation) for pasting into a ticket.
- If feasible without backend churn, an inline **triage** control (mark false-positive / accepted-risk) — but only wire it if there is an existing persistence path; otherwise leave a clearly-disabled affordance and note it. Do **not** fabricate a fake persistence.
- *Acceptance:* deep-linking to `#f-<id>` opens and scrolls to that finding; "Copy as Markdown" yields paste-ready text.

**T2.5 [P1] Show scan configuration (reproducibility).** Add a compact, collapsible "Scan configuration" block (in the Summary or the header's overflow) showing what ran: enabled scanners, auth mode (`none`/manual/profile — never render secrets/tokens), crawler max pages, aggressive flag, started/finished, duration. Source: `scan.selection`, `scan.target`, `scan.meta`.
- *Acceptance:* a reader can reproduce the scan from what's shown; **no secrets** (bearer tokens, cookies, passwords) are ever displayed.

**T2.6 [P1] Fix + expand export (fixes D2).** Add a real **self-contained HTML report** route (e.g. `app/api/scans/[id]/report/route.ts?format=html` or a sibling) that inlines its own minimal CSS (must render standalone, offline, print-friendly) and mirrors the Summary: header, severity table, top-ROI, full findings with remediation. Point the ScanHeader menu item at it. Also expose the existing **exec-summary** and **markdown** formats in the menu as distinct items. Reuse `rankFindings`.
- *Acceptance:* "Export HTML report" downloads a valid `.html` that opens offline and prints cleanly; the menu labels match what each item actually returns.

**T2.7 [P2] Print stylesheet for the on-screen report.** Add `@media print` rules (in `globals.css` or a scoped block) so the scan-detail page prints to PDF as a clean report: hide the sidebar/app chrome/footer/tab bar, expand all findings, drop glass blur, force readable light-on-white, keep severity color as text. "Print to PDF" is the most common real-world share path — make it look intentional.
- *Acceptance:* `Ctrl/Cmd+P` on a completed scan yields a professional multi-page PDF, no app chrome.

**T2.8 [P2] Failed/cancelled report states.** Design explicit states: a `failed` scan shows the error prominently with a retry CTA; a `cancelled` scan explains partial results are retained. (`scan.status` + `scan.errorMessage` already exist.)

---

## Phase 3 — Necessary supporting changes (do after 1 & 2)

**T3.1 [P1] Manual light/dark theme toggle.** Today theme follows `prefers-color-scheme` only. Add a header control (in `AppShell` header) that toggles light/dark/system, persisted to `localStorage`, applied via a `data-theme` attribute on `<html>`. Update `globals.css` so the dark token block responds to **both** `@media (prefers-color-scheme: dark)` **and** `:root[data-theme="dark"]` (and force light under `[data-theme="light"]`). Avoid FOUC (set the attribute before paint via a tiny inline script in `app/layout.tsx`, following the Next 16 docs for injecting pre-hydration scripts).
- *Acceptance:* toggle persists across reloads; system mode tracks the OS; no flash of wrong theme on load.

**T3.2 [P1] Mobile navigation (fixes D4).** Add a working mobile nav to `AppShell` (top slide-over drawer or bottom tab bar) exposing all sidebar destinations, with the active state and `aria-current`. Ensure the main flow is fully operable at 375px width.
- *Acceptance:* on a 375px viewport you can reach Overview / Web / Source / Scans / Tools and see which is active.

**T3.3 [P2] Shared toast system.** `ScanHeader` hand-rolls an absolute-positioned toast. Extract a minimal toast context/provider (mounted in `AppShell`) and reuse it for the new copy/triage/export actions so feedback is consistent. Keep it dependency-free and accessible (`role="status"`, auto-dismiss, focus-safe).

**T3.4 [P2] Consistency sweep.** Extract the repeated hero/brand gradient (`app/page.tsx` and `AppShell.tsx`) into a token or utility class. Ensure empty states, severity chips, and glass tiers are used consistently across dashboard, scans list, and report.

---

## 6. Definition of done

- All **P0** and **P1** tasks implemented; **P2** implemented where time allows (list any deferred).
- Defects **D1–D4** resolved.
- `npx tsc --noEmit` clean, `npm run lint` clean, `npm run build` succeeds.
- No new runtime dependencies (or each justified in the PR body).
- Works and looks correct in **light and dark**, at **375px, 768px, and 1280px**, and with **reduced motion**.
- Keyboard-only: every new control reachable, operable, and visibly focused. No color-only severity signaling.
- No secrets ever rendered in the report/config views.
- Every headline metric is provably correct against `data/index.json`.

## 7. How to verify (do this, don't hand-wave)

1. **Run the app.** Create `.claude/launch.json` with a dev server config (`npm run dev`) and use the preview tools — never ask the user to check manually. If not using the harness: `npm run dev` and open the pages.
2. **Seed data if empty.** To exercise the report you need a completed scan. Start one from `/scan/web` against a reachable demo target (the form offers `http://juice-shop:3000/` when the demo sidecar is up via `docker compose --profile demo up`, or the public `http://demo.testfire.net/`). Confirm findings appear, then work the report against real data.
3. **Drive each surface:** dashboard KPIs vs. `data/index.json`; start a scan and confirm it shows as active on `/`; open a completed scan, click a severity tile → filtered findings; deep-link `#f-<id>`; export HTML and open the file offline; `Ctrl/Cmd+P` to check print.
4. **Toggle theme and resize** to validate T3.1/T3.2. Check console for errors and the network tab for the export routes.
5. Capture before/after screenshots (light + dark) for the PR.

## 8. Out of scope / do NOT

- No redesign of the scan *creation* forms beyond consistency touch-ups (they're solid).
- No change to the scanning engine, adapters, SSE event shapes, or `lib/store.ts` persistence format.
- No new dependencies for charts/animation/UI unless justified and approved.
- Do not weaken the "authorized testing only" messaging.
- Do not display auth secrets anywhere.

## 9. Suggested commit / PR plan

Branch per phase or one feature branch with tidy commits:
1. `feat(dashboard): posture KPIs, active-scan strip, consistent recent list` (Phase 1, fixes D1/D3)
2. `feat(report): summary tab, interactive severity counters, findings filters/sort/group` (T2.1–T2.3)
3. `feat(report): per-finding actions, scan config, HTML export + print` (T2.4–T2.7, fixes D2)
4. `feat(ui): theme toggle, mobile nav, shared toasts, consistency` (Phase 3, fixes D4)

PR description: what changed, screenshots (light/dark, mobile), how verified, any P2 deferred, any dependency justification.

---

### Appendix — quick code facts to save exploration time

- Params are async: `export default async function Page(props: PageProps<"/scans/[id]">) { const { id } = await props.params; }`.
- Route handler params: `async function GET(req, ctx: RouteContext<"/api/scans/[id]/report">) { const { id } = await ctx.params; }`.
- Severity vars: `var(--md-severity-critical|high|medium|low|info)`; rank map `SEVERITY_RANK` and `EMPTY_COUNTS` in `lib/types.ts`.
- `Finding` has `severity`, `confidence`, `cvss?`, `cwe?/cve?/owasp?`, `location.{url,file,line,snippet}`, `remediation?`, `references?`, `triage?`, `createdAt`.
- Tabs sync to `?tab=<id>` (`components/scan-tabs/Tabs.tsx`) — reuse this URL-state pattern for severity deep-links rather than inventing local state.
- Ranking for reports: `rankFindings(findings)` in `lib/triage/ranker.ts` returns `{ id, rank, score, reason, finding }[]` sorted by descending ROI score (`rank` is 1-based). It scores by severity × confidence × exploitability (active vs passive rule class, `chain`/OOB bumps) × asset value (high-value URL paths like `/login`, `/admin`, `/payment`). Reuse it — do not re-implement ranking in the UI.
- Glass tiers, typography classes, severity ramp, and state-layer utility are all defined in `app/globals.css`.

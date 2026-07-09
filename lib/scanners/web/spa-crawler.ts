/**
 * SPA crawler — headless Chromium counterpart to the regex-based crawler.
 *
 * The static crawler matches HTML / JS with regexes, which misses anything
 * a real browser would only see after JS runs: Next.js / React Router pages,
 * components fetched in useEffect, modal forms that only render after a
 * click. This scanner spins up a real browser, navigates, listens for
 * `request` (every XHR/fetch becomes an endpoint discovery) and
 * `framenavigated` (every SPA route push becomes a URL discovery), then
 * harvests post-render DOM anchors + forms.
 *
 * Beyond navigation it runs an INTERACTION PASS (Acunetix DeepScan-style):
 * on each page it enumerates candidate interactive elements (buttons, tabs,
 * menus, disclosure widgets, `cursor:pointer` non-anchors, SPA router links
 * with no `<a href>`), clicks them within strict budgets, and captures the
 * state each click reveals — modals, accordion panels, lazy-rendered content,
 * new XHR endpoints and pushState routes the navigation-only crawler cannot
 * reach. Destructive controls (logout / delete / payment / …) are never
 * clicked; form submitters fire only under `aggressive`. See `_interaction.ts`.
 *
 * Discovered items go straight into the DiscoveryBus via ctx.discover, so
 * form-fuzzer / content-discovery / query-fuzzer / other consumers re-process
 * them in the consumer phase the runner runs after static waves.
 *
 * Heavy by design — defaultEnabled: false and parallelSafe: false.
 * Honors `target.auth.profileId` by loading the captured storageState into
 * the browser context (real authenticated SPA crawl).
 */

import { draft, type Scanner } from "../../engine/scanner";
import type { HttpMethod } from "../../engine/discovery";
import { safeUrl } from "../common";
import { loadProfile } from "../../auth/profile";
import {
  harvestDom,
  runInteractionPass,
  type HarvestedForm,
  type InteractionStats,
} from "./_interaction";

let chromiumPromise: Promise<typeof import("playwright-core").chromium> | null = null;
async function getChromium() {
  if (!chromiumPromise) chromiumPromise = import("playwright-core").then((m) => m.chromium);
  return chromiumPromise;
}

const HTTP_METHODS: ReadonlySet<HttpMethod> = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
]);

function asMethod(s: string): HttpMethod {
  const up = s.toUpperCase();
  return (HTTP_METHODS.has(up as HttpMethod) ? up : "GET") as HttpMethod;
}

const SKIPPED_RESOURCE_TYPES = new Set([
  "image",
  "font",
  "stylesheet",
  "media",
  "manifest",
  "other",
]);

/** Per-click actionability timeout inside the interaction pass. */
const CLICK_TIMEOUT_MS = 2_500;
/** Post-click settle window (raced against networkidle). */
const SETTLE_MS = 800;

/** Read an integer option with a default + clamp. */
function clampInt(v: unknown, def: number, min: number, max: number): number {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

export const spaCrawlerScanner: Scanner = {
  id: "web.spa-crawler",
  name: "SPA Crawler (Headless Chromium)",
  kind: "web",
  description:
    "Real browser crawl: catches React/Vue/Next route pushes, XHR/fetch endpoints, post-render forms — everything the regex crawler misses. Adds an interaction pass that clicks buttons/tabs/menus to reach modals, lazy-rendered content and onClick-only SPA routes. Never clicks destructive controls. Loads captured login profiles for authenticated SPA crawl. Heavy (opt-in).",
  defaultEnabled: false,
  parallelSafe: false,

  async tool() {
    return {
      id: "web.spa-crawler",
      name: "SPA Crawler",
      kind: "web",
      backend: "library",
      status: "available",
      description: "Built-in Playwright-driven SPA discovery with interaction-driven state exploration.",
      upstream: "https://playwright.dev",
    };
  },

  async run(ctx) {
    const start = safeUrl(ctx.target.value);
    if (!start) {
      await ctx.log("error", "invalid URL");
      return;
    }
    const maxPages = Math.min(Math.max(Number(ctx.options.spaMaxPages) || 30, 1), 100);
    const pageBudget = Math.min(
      Math.max(Number(ctx.options.spaPageBudgetMs) || 15_000, 3_000),
      60_000,
    );

    // Interaction-pass tuning (all optional; sensible defaults). `aggressive`
    // mirrors the repo-wide convention (AGGRESSIVE_SCANNERS in scan/web/page).
    const aggressive = Boolean(ctx.options.aggressive);
    const perPageInteractions = clampInt(ctx.options.maxInteractionsPerPage, 20, 0, 50);
    const interactionDepth = clampInt(ctx.options.spaInteractionDepth, 2, 1, 4);
    const interactionBudgetMs = clampInt(ctx.options.spaInteractionBudgetMs, 20_000, 3_000, 60_000);
    // Global click ceiling across every page — defends against a template that
    // renders hundreds of clickables per page multiplied across the crawl.
    const globalInteractionCap = clampInt(
      ctx.options.spaMaxInteractions,
      Math.min(perPageInteractions * maxPages, 300),
      Math.max(perPageInteractions, 1),
      2000,
    );
    const globalBudget = { remaining: globalInteractionCap };

    let chromium: Awaited<ReturnType<typeof getChromium>>;
    try {
      chromium = await getChromium();
    } catch (e) {
      await ctx.log(
        "error",
        `playwright-core failed to load: ${e instanceof Error ? e.message : e}. Open the scan-setup page → Captured session → Install Chromium.`,
      );
      return;
    }

    let browser: Awaited<ReturnType<typeof chromium.launch>>;
    try {
      browser = await chromium.launch({ headless: true });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      await ctx.log(
        "error",
        `chromium launch failed: ${msg}. Open the scan-setup page → Captured session → Install Chromium (one click).`,
      );
      await ctx.emit(draft({
        severity: "info",
        confidence: "high",
        title: "SPA crawler skipped — Chromium not installed",
        description:
          "Open /scan/web → Authentication → Captured session and use the Install Chromium button. Then re-run with web.spa-crawler enabled.",
        ruleId: "spa-crawler/no-chromium",
        location: { url: ctx.target.value },
      }));
      return;
    }

    try {
      const profileId = ctx.target.auth?.profileId;
      const storageState = profileId
        ? (await loadProfile(profileId).catch(() => null)) ?? undefined
        : undefined;
      if (profileId) {
        await ctx.log(
          "info",
          storageState
            ? `loaded login profile "${profileId}" (${storageState.cookies?.length ?? 0} cookies)`
            : `login profile "${profileId}" not found in vault — proceeding unauthenticated`,
        );
      }

      const context = await browser.newContext({
        userAgent: "moba-scanner/0.1 (+spa-crawler)",
        ignoreHTTPSErrors: true,
        storageState: storageState as Parameters<typeof browser.newContext>[0] extends infer C
          ? C extends { storageState?: infer S } ? S : never
          : never,
      });

      const seen = new Set<string>([start.toString()]);
      const queue: string[] = [start.toString()];
      let processed = 0;
      let endpointHits = 0;
      let formHits = 0;
      let routeHits = 0;

      // Interaction attribution: flip `interacting` around each page's pass so
      // the request/framenavigated listeners can tag NEW discoveries as
      // interaction-driven (vs. surfaced by the initial load).
      let interacting = false;
      let interactionEndpoints = 0;
      let interactionRoutes = 0;
      const ix: InteractionStats = {
        candidates: 0,
        clicked: 0,
        skippedDestructive: 0,
        skippedFormSubmit: 0,
        skippedOther: 0,
        revealedForms: 0,
        revealedAnchors: 0,
      };

      /** Publish revealed anchors through the crawler's dedupe (seen/queue) and
       *  the bus. Returns the count that was genuinely new. Shared by the
       *  initial harvest and the interaction re-harvests. */
      const publishAnchors = (anchors: string[], via: string, pageUrl: string): number => {
        let created = 0;
        for (const href of anchors) {
          try {
            const u = new URL(href);
            if (u.origin !== start.origin) continue;
            const s = u.toString();
            if (seen.has(s)) continue;
            seen.add(s);
            if (queue.length + processed < maxPages * 2) queue.push(s);
            const isNew = ctx.discover({
              kind: "url",
              url: s,
              source: { scannerId: "web.spa-crawler", via, parentUrl: pageUrl },
            });
            if (isNew) created += 1;
          } catch {
            /* skip malformed href */
          }
        }
        return created;
      };

      /** Publish revealed forms through the bus. Returns the count that was new. */
      const publishForms = (forms: HarvestedForm[], via: string, pageUrl: string): number => {
        let created = 0;
        for (const f of forms) {
          const method: "GET" | "POST" = f.method === "POST" ? "POST" : "GET";
          const isNew = ctx.discover({
            kind: "form",
            form: {
              pageUrl,
              action: f.action,
              method,
              inputs: f.inputs,
              looksLikeLogin: f.inputs.some((i) => i.type === "password"),
              hasCsrfToken: f.inputs.some((i) => /(csrf|xsrf|authenticity_token|_token)/i.test(i.name)),
            },
            source: { scannerId: "web.spa-crawler", via, parentUrl: pageUrl },
          });
          if (isNew) created += 1;
        }
        return created;
      };

      while (queue.length && processed < maxPages && !ctx.signal.aborted) {
        const url = queue.shift()!;
        processed += 1;
        await ctx.progress(processed / maxPages, `${processed}/${maxPages} ${url}`);

        const page = await context.newPage();
        try {
          // Live XHR/fetch capture. Skip noise (images, fonts, css) — the
          // useful signal is requests the JS makes to APIs.
          page.on("request", (req) => {
            try {
              const rt = req.resourceType();
              if (SKIPPED_RESOURCE_TYPES.has(rt)) return;
              const u = req.url();
              if (new URL(u).origin !== start.origin) return;
              const isNew = ctx.discover({
                kind: "endpoint",
                url: u,
                method: asMethod(req.method()),
                source: { scannerId: "web.spa-crawler", via: `${rt}-${req.method().toLowerCase()}`, parentUrl: url },
              });
              endpointHits += 1;
              if (interacting && isNew) interactionEndpoints += 1;
            } catch { /* skip */ }
          });

          // SPA route changes (pushState / replaceState) surface as
          // framenavigated on the main frame.
          page.on("framenavigated", (frame) => {
            try {
              if (frame !== page.mainFrame()) return;
              const u = frame.url();
              if (new URL(u).origin !== start.origin) return;
              if (u === url || seen.has(u)) return;
              seen.add(u);
              if (queue.length + processed < maxPages * 2) queue.push(u);
              const isNew = ctx.discover({
                kind: "url",
                url: u,
                source: { scannerId: "web.spa-crawler", via: "framenavigated", parentUrl: url },
              });
              routeHits += 1;
              if (interacting && isNew) interactionRoutes += 1;
            } catch { /* skip */ }
          });

          // Initial nav. Use domcontentloaded then wait separately for
          // networkidle — pages with long-poll connections never hit
          // networkidle alone and would hang the budget.
          await page.goto(url, { waitUntil: "domcontentloaded", timeout: pageBudget });
          await Promise.race([
            page
              .waitForLoadState("networkidle", { timeout: pageBudget })
              .catch(() => undefined),
            new Promise((r) => setTimeout(r, pageBudget)),
          ]);

          // Harvest post-render anchors + forms, then publish them.
          const harvested = await harvestDom(page);
          publishAnchors(harvested.anchors, "anchor-postrender", url);
          formHits += publishForms(harvested.forms, "form-postrender", url);

          // ── Interaction pass ────────────────────────────────────────────
          // Reach states hidden behind clicks. Guarded by budgets + abort.
          if (perPageInteractions > 0 && globalBudget.remaining > 0 && !ctx.signal.aborted) {
            interacting = true;
            try {
              const s = await runInteractionPass({
                page,
                signal: ctx.signal,
                origin: start.origin,
                pageUrl: url,
                aggressive,
                perPageBudget: perPageInteractions,
                maxDepth: interactionDepth,
                globalBudget,
                timeBudgetMs: interactionBudgetMs,
                clickTimeoutMs: CLICK_TIMEOUT_MS,
                settleMs: SETTLE_MS,
                publishAnchors,
                publishForms,
                log: (level, message) => ctx.log(level, message),
              });
              ix.candidates += s.candidates;
              ix.clicked += s.clicked;
              ix.skippedDestructive += s.skippedDestructive;
              ix.skippedFormSubmit += s.skippedFormSubmit;
              ix.skippedOther += s.skippedOther;
              ix.revealedForms += s.revealedForms;
              ix.revealedAnchors += s.revealedAnchors;
            } catch (e) {
              await ctx.log("warn", `interaction pass on ${url}: ${e instanceof Error ? e.message : e}`);
            } finally {
              interacting = false;
            }
          }
        } catch (e) {
          await ctx.log("warn", `${url}: ${e instanceof Error ? e.message : e}`);
        } finally {
          await page.close().catch(() => undefined);
        }
      }

      await context.close().catch(() => undefined);

      const totalForms = formHits + ix.revealedForms;
      await ctx.emit(draft({
        severity: "info",
        confidence: "high",
        title:
          `SPA crawl: ${processed} page(s), ${routeHits} routes, ${endpointHits} XHR/fetch, ${totalForms} forms` +
          ` — interaction fired ${ix.clicked}/${ix.candidates} candidate(s)` +
          ` (skipped ${ix.skippedDestructive} destructive), revealing` +
          ` +${interactionRoutes} route(s), +${interactionEndpoints} XHR/fetch, +${ix.revealedForms} form(s)`,
        description:
          "Headless-browser surface discovered. Beyond navigation, an interaction pass clicked buttons / tabs / menus / disclosure widgets to reach application states hidden behind onClick handlers (modals, SPA router links with no <a href>, lazy-rendered content). Destructive controls (logout / delete / payment / …) were never clicked" +
          (aggressive ? "; aggressive mode also submitted non-destructive forms." : ".") +
          " Each item was fed into the DiscoveryBus so other scanners (form-fuzzer, query-fuzzer, content-discovery, …) can probe them.",
        ruleId: "spa-crawler/summary",
        location: { url: ctx.target.value },
        evidence: {
          processed,
          routeHits,
          endpointHits,
          formHits,
          maxPages,
          interaction: {
            aggressive,
            perPageBudget: perPageInteractions,
            maxDepth: interactionDepth,
            globalCap: globalInteractionCap,
            globalRemaining: globalBudget.remaining,
            candidates: ix.candidates,
            clicked: ix.clicked,
            skippedDestructive: ix.skippedDestructive,
            skippedFormSubmit: ix.skippedFormSubmit,
            skippedOther: ix.skippedOther,
            newRoutes: interactionRoutes,
            newEndpoints: interactionEndpoints,
            newForms: ix.revealedForms,
            newAnchorUrls: ix.revealedAnchors,
          },
        },
      }));
    } finally {
      await browser.close().catch(() => undefined);
    }

    await ctx.progress(1, "spa-crawler done");
  },
};

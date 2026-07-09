/**
 * Interaction engine for the SPA crawler — the "DeepScan" part.
 *
 * The navigation-only crawler (spa-crawler.ts) sees whatever a real browser
 * renders after load: anchors, post-render forms, XHR endpoints, framenavigated
 * route pushes. What it CANNOT see is application state hidden behind a click —
 * modals, accordion / tab panels, pop-up menus, "load more" lazy render, and
 * SPA router links implemented as `onClick` handlers with NO `<a href>`.
 *
 * This module adds that: on each page it enumerates candidate interactive
 * elements, clicks them within strict budgets, and captures what each click
 * reveals (new anchors / forms / XHR / SPA routes), publishing everything back
 * through the crawler's discovery closures so downstream consumers
 * (form-fuzzer, query-fuzzer, …) re-probe it.
 *
 * SAFETY is first-class: destructive controls (logout / delete / payment / …)
 * are never clicked, and form-submitting controls fire only under `aggressive`.
 *
 * Imported ONLY by spa-crawler.ts. No engine / SiteMap imports here — the
 * crawler passes in publish closures so this stays a pure interaction layer.
 */

import type { Page, ElementHandle } from "playwright-core";

/** A form-input shape the crawler turns into a SiteMapForm. */
export interface HarvestedInput {
  name: string;
  type: string;
  value?: string;
  required?: boolean;
}

export interface HarvestedForm {
  action: string;
  method: string;
  inputs: HarvestedInput[];
}

export interface Harvested {
  anchors: string[];
  forms: HarvestedForm[];
}

/** A clickable element found on the page. `sig` is a stable fingerprint used
 *  to dedupe / avoid re-clicking; `selector` re-locates it against the live
 *  DOM (which may mutate between enumeration and click). */
export interface Candidate {
  sig: string;
  selector: string;
  tag: string;
  role: string;
  text: string;
  label: string;
  /** True iff clicking this submits an owning <form> (input/button type
   *  submit|image with a form owner). Gated behind `aggressive`. */
  submits: boolean;
}

export interface InteractionStats {
  /** Distinct candidates enumerated across all depths. */
  candidates: number;
  /** Elements actually clicked. */
  clicked: number;
  /** Candidates skipped because their label matched the destructive blocklist. */
  skippedDestructive: number;
  /** Form-submitting candidates skipped because the scan wasn't aggressive. */
  skippedFormSubmit: number;
  /** Candidates skipped for other reasons (gone from DOM, not actionable). */
  skippedOther: number;
  /** New forms revealed by clicks (dedup-survived). */
  revealedForms: number;
  /** New anchor / landing URLs revealed by clicks (dedup-survived). */
  revealedAnchors: number;
}

/** Everything the interaction pass needs from its caller. The crawler owns the
 *  browser page, the discovery bus wiring (via the publish closures), the
 *  origin/URL bookkeeping and the budgets. */
export interface InteractionDeps {
  page: Page;
  signal: AbortSignal;
  /** Origin of the scan target — off-origin navigations are not chased. */
  origin: string;
  /** URL of the page being interacted on (the state we restore to). */
  pageUrl: string;
  /** Aggressive scans may fire form-submit controls; default scans never do. */
  aggressive: boolean;
  /** Max clicks on THIS page (0 disables the pass). */
  perPageBudget: number;
  /** How many "reveal a candidate then click it" levels to descend. */
  maxDepth: number;
  /** Shared, mutable global click budget across every page. */
  globalBudget: { remaining: number };
  /** Wall-clock ceiling for THIS page's interaction pass. */
  timeBudgetMs: number;
  clickTimeoutMs: number;
  settleMs: number;
  /** Publish revealed anchors/forms through the crawler's dedupe+bus. Each
   *  returns the count that was actually new (survived clustering). */
  publishAnchors: (anchors: string[], via: string, pageUrl: string) => number;
  publishForms: (forms: HarvestedForm[], via: string, pageUrl: string) => number;
  /** Optional log passthrough. */
  log?: (level: "info" | "warn" | "error", message: string) => Promise<void>;
}

/**
 * SAFETY BLOCKLIST. Any candidate whose visible text / aria-label / title
 * matches this is NEVER clicked — even in aggressive mode. Covers session
 * teardown, data destruction, account changes and anything that spends money
 * or "confirms" an irreversible action.
 */
export const DESTRUCTIVE_RE =
  /log\s*-?\s*out|sign\s*-?\s*out|logout|delete|remove|destroy|deactivate|close account|transfer|withdraw|pay|purchase|buy|checkout|place order|confirm|reset|revoke|unsubscribe/i;

export function isDestructiveText(s?: string | null): boolean {
  if (!s) return false;
  return DESTRUCTIVE_RE.test(s);
}

/**
 * Post-render harvest of anchors + forms. Identical shape to what the crawler
 * captured inline before — factored here so the interaction pass can re-harvest
 * after each click without duplicating the extraction logic.
 */
export async function harvestDom(page: Page): Promise<Harvested> {
  return page.evaluate(() => {
    const anchors = Array.from(document.querySelectorAll("a[href]"))
      .map((a) => (a as HTMLAnchorElement).href)
      .filter(
        (h) =>
          h &&
          !h.startsWith("javascript:") &&
          !h.startsWith("mailto:") &&
          !h.startsWith("tel:"),
      );
    const forms = Array.from(document.querySelectorAll("form")).map((f) => {
      const form = f as HTMLFormElement;
      const inputs = Array.from(form.querySelectorAll("input,select,textarea"))
        .map((el) => {
          const e = el as HTMLInputElement;
          return {
            name: e.name,
            type: (e.type || "text").toLowerCase(),
            value: e.value,
            required: e.required,
          };
        })
        .filter((i) => i.name);
      return {
        action: form.action || location.href,
        method: (form.method || "GET").toUpperCase(),
        inputs,
      };
    });
    return { anchors, forms };
  });
}

/**
 * Enumerate candidate interactive elements and return a stable signature +
 * unique CSS selector for each. Runs entirely in-page (one round-trip).
 *
 * Candidates:
 *   - <button>, [role=button|tab|menuitem|menuitemcheckbox|switch]
 *   - <summary>, [aria-expanded], [aria-haspopup], [data-toggle]/[data-bs-toggle]
 *   - any element with computed `cursor: pointer` that is NOT a native control
 *     and NOT inside an <a href> (those are already harvested as navigation).
 */
export async function enumerateCandidates(page: Page): Promise<Candidate[]> {
  return page.evaluate(() => {
    const MAX = 400;
    const out: Array<{
      sig: string;
      selector: string;
      tag: string;
      role: string;
      text: string;
      label: string;
      submits: boolean;
    }> = [];
    const seen = new Set<string>();

    const esc = (s: string): string =>
      typeof CSS !== "undefined" && typeof CSS.escape === "function"
        ? CSS.escape(s)
        : s.replace(/[^a-zA-Z0-9_-]/g, "\\$&");

    const uniqueId = (el: Element): string | null => {
      if (!el.id) return null;
      try {
        if (document.querySelectorAll("#" + esc(el.id)).length === 1) return "#" + esc(el.id);
      } catch {
        /* invalid id for a selector */
      }
      return null;
    };

    // Build a reasonably-unique selector: prefer a unique id anywhere on the
    // path, else a short :nth-of-type chain (capped depth).
    const cssPath = (el: Element): string => {
      const direct = uniqueId(el);
      if (direct) return direct;
      const parts: string[] = [];
      let node: Element | null = el;
      let hops = 0;
      while (node && node.nodeType === 1 && hops < 6) {
        const cur: Element = node;
        const idSel = uniqueId(cur);
        if (idSel) {
          parts.unshift(idSel);
          return parts.join(" > ");
        }
        let sel = cur.tagName.toLowerCase();
        const parent: Element | null = cur.parentElement;
        if (parent) {
          const sameTag = Array.from(parent.children).filter((c) => c.tagName === cur.tagName);
          if (sameTag.length > 1) sel += ":nth-of-type(" + (sameTag.indexOf(cur) + 1) + ")";
        }
        parts.unshift(sel);
        node = cur.parentElement;
        hops++;
      }
      return parts.join(" > ");
    };

    const insideAnchor = (el: Element): boolean => {
      let n: Element | null = el;
      while (n) {
        if (n.tagName === "A" && (n as HTMLAnchorElement).hasAttribute("href")) return true;
        n = n.parentElement;
      }
      return false;
    };

    const textOf = (el: Element): { text: string; label: string } => {
      const label = (el.getAttribute("aria-label") || el.getAttribute("title") || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 120);
      const text = (el.textContent || "").replace(/\s+/g, " ").trim().slice(0, 120);
      return { text, label };
    };

    const submitsForm = (el: Element): boolean => {
      const owner = (el as HTMLButtonElement | HTMLInputElement).form;
      if (!owner) return false;
      const t = ((el as HTMLButtonElement | HTMLInputElement).type || "").toLowerCase();
      return t === "submit" || t === "image";
    };

    const EXPLICIT = [
      "button",
      "[role=button]",
      "[role=tab]",
      "[role=menuitem]",
      "[role=menuitemcheckbox]",
      "[role=switch]",
      "summary",
      "[aria-expanded]",
      "[aria-haspopup]",
      "[data-toggle]",
      "[data-bs-toggle]",
    ].join(",");

    const pool: Element[] = [];
    for (const el of Array.from(document.querySelectorAll(EXPLICIT))) pool.push(el);

    // Clickable non-anchors: computed cursor:pointer, not a native form control,
    // not an anchor. Bounded scan so a huge DOM can't stall the round-trip.
    let scanned = 0;
    for (const el of Array.from(document.querySelectorAll("body *"))) {
      if (scanned > 4000 || pool.length > 800) break;
      scanned++;
      const tag = el.tagName;
      if (
        tag === "A" ||
        tag === "BUTTON" ||
        tag === "INPUT" ||
        tag === "SELECT" ||
        tag === "TEXTAREA" ||
        tag === "OPTION" ||
        tag === "LABEL"
      )
        continue;
      const st = getComputedStyle(el);
      if (
        st.cursor === "pointer" &&
        st.pointerEvents !== "none" &&
        st.visibility !== "hidden" &&
        st.display !== "none"
      ) {
        pool.push(el);
      }
    }

    for (const el of pool) {
      if (out.length >= MAX) break;
      if (insideAnchor(el)) continue;
      const st = getComputedStyle(el);
      if (st.display === "none" || st.visibility === "hidden" || st.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) continue;
      const role = el.getAttribute("role") || "";
      const { text, label } = textOf(el);
      const selector = cssPath(el);
      if (!selector) continue;
      const sig = el.tagName.toLowerCase() + "|" + role + "|" + (text || label) + "|" + selector;
      if (seen.has(sig)) continue;
      seen.add(sig);
      out.push({
        sig,
        selector,
        tag: el.tagName.toLowerCase(),
        role,
        text,
        label,
        submits: submitsForm(el),
      });
    }
    return out;
  });
}

function curUrl(page: Page): string {
  try {
    return page.url();
  } catch {
    return "";
  }
}

function sameOrigin(u: string, origin: string): boolean {
  try {
    return new URL(u).origin === origin;
  } catch {
    return false;
  }
}

/** Bounded settle: resolve as soon as the network is idle OR `settleMs`
 *  elapses, never past the page's overall interaction deadline. */
async function settle(page: Page, settleMs: number, deadline: number): Promise<void> {
  const budget = Math.max(0, Math.min(settleMs, deadline - Date.now()));
  if (budget <= 0) return;
  await Promise.race([
    page.waitForLoadState("networkidle", { timeout: budget }).catch(() => undefined),
    page.waitForTimeout(budget),
  ]).catch(() => undefined);
}

/** After a click navigated away, get back to the base state so the remaining
 *  candidates can still be exercised: history back first, hard re-goto if that
 *  overshoots or fails. Best-effort — a failure just means fewer candidates. */
async function restore(page: Page, baseUrl: string, settleMs: number, deadline: number): Promise<void> {
  try {
    await page.goBack({ timeout: Math.max(1500, settleMs * 2), waitUntil: "domcontentloaded" });
  } catch {
    /* maybe no history entry — fall through to re-goto */
  }
  if (curUrl(page) !== baseUrl && Date.now() < deadline) {
    try {
      await page.goto(baseUrl, { timeout: Math.max(3000, settleMs * 3), waitUntil: "domcontentloaded" });
    } catch {
      /* best-effort */
    }
  }
  await settle(page, settleMs, deadline);
}

/** Fill the form owning `handle` with benign, type-appropriate values so an
 *  aggressive submit carries plausible data. Never touches submit controls. */
async function fillOwningForm(handle: ElementHandle<SVGElement | HTMLElement>): Promise<void> {
  try {
    await handle.evaluate((node) => {
      const owner = (node as HTMLButtonElement | HTMLInputElement).form;
      if (!owner) return;
      const skip = new Set(["submit", "button", "reset", "image", "hidden", "file", "checkbox", "radio"]);
      const setVal = (input: HTMLInputElement | HTMLTextAreaElement, v: string) => {
        try {
          input.value = v;
          input.dispatchEvent(new Event("input", { bubbles: true }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
        } catch {
          /* ignore a single stubborn input */
        }
      };
      for (const raw of Array.from(owner.querySelectorAll("input,textarea"))) {
        const input = raw as HTMLInputElement;
        const t = (input.type || "text").toLowerCase();
        if (skip.has(t) || input.value) continue;
        if (t === "email") setVal(input, "moba-test@example.com");
        else if (t === "number" || t === "range") setVal(input, "1");
        else if (t === "url") setVal(input, "https://example.com");
        else if (t === "tel") setVal(input, "5551234567");
        else if (t === "password") setVal(input, "Moba-Passw0rd!");
        else if (t === "date") setVal(input, "2025-01-01");
        else setVal(input, "moba-baseline");
      }
    });
  } catch {
    /* best-effort fill */
  }
}

/**
 * Run the interaction pass on one already-loaded page.
 *
 * Algorithm:
 *   1. Enumerate candidates → seed a work queue at depth 0.
 *   2. For each candidate (within per-page + global + time budgets):
 *      - Skip destructive controls (always) and form submitters (unless
 *        aggressive).
 *      - Re-locate against the live DOM; re-check the destructive filter on the
 *        element's live accessible text.
 *      - Click (bounded). Detect navigation by URL change — even if the click
 *        threw because it destroyed its own execution context.
 *      - Navigation: publish the landing URL, then restore to the base state.
 *      - No navigation: re-harvest anchors/forms + re-enumerate; new candidate
 *        signatures are enqueued at depth+1 (up to maxDepth).
 *   3. A per-page visited-signature set + hard budgets guarantee termination.
 */
export async function runInteractionPass(deps: InteractionDeps): Promise<InteractionStats> {
  const {
    page,
    signal,
    origin,
    pageUrl,
    aggressive,
    perPageBudget,
    maxDepth,
    globalBudget,
    timeBudgetMs,
    clickTimeoutMs,
    settleMs,
    publishAnchors,
    publishForms,
    log,
  } = deps;

  const stats: InteractionStats = {
    candidates: 0,
    clicked: 0,
    skippedDestructive: 0,
    skippedFormSubmit: 0,
    skippedOther: 0,
    revealedForms: 0,
    revealedAnchors: 0,
  };

  if (perPageBudget <= 0 || globalBudget.remaining <= 0) return stats;

  const deadline = Date.now() + timeBudgetMs;
  const visited = new Set<string>();
  const queued = new Set<string>();
  const work: Array<{ c: Candidate; depth: number }> = [];

  let initial: Candidate[];
  try {
    initial = await enumerateCandidates(page);
  } catch {
    return stats;
  }
  for (const c of initial) {
    if (!queued.has(c.sig)) {
      queued.add(c.sig);
      work.push({ c, depth: 0 });
    }
  }

  while (
    work.length &&
    stats.clicked < perPageBudget &&
    globalBudget.remaining > 0 &&
    !signal.aborted &&
    Date.now() < deadline
  ) {
    const { c, depth } = work.shift()!;
    if (visited.has(c.sig)) continue;
    visited.add(c.sig);

    // SAFETY: never trigger destructive controls (logout / delete / pay / …).
    if (isDestructiveText(c.text) || isDestructiveText(c.label)) {
      stats.skippedDestructive++;
      continue;
    }
    // SAFETY: a form submitter mutates server state — aggressive-only.
    if (c.submits && !aggressive) {
      stats.skippedFormSubmit++;
      continue;
    }

    // Re-locate against the LIVE DOM (it may have mutated since enumeration).
    let located: Awaited<ReturnType<Page["$"]>> = null;
    try {
      located = await page.$(c.selector);
    } catch {
      located = null;
    }
    if (!located) {
      stats.skippedOther++;
      continue;
    }
    const el = located;

    try {
      // Belt-and-suspenders: re-read live accessible text; a signature captured
      // earlier could point at an element whose label changed to a dangerous one.
      let live = "";
      try {
        live = (await el.evaluate((n) => {
          const e = n as HTMLElement;
          return (
            (e.textContent || "") +
            " " +
            (e.getAttribute("aria-label") || "") +
            " " +
            (e.getAttribute("title") || "")
          ).trim();
        })) as string;
      } catch {
        /* fall back to enumeration text (already filtered) */
      }
      if (isDestructiveText(live)) {
        stats.skippedDestructive++;
        continue;
      }

      // Aggressive: populate the owning form before submitting it.
      if (aggressive && c.submits) await fillOwningForm(el);

      const before = curUrl(page);
      let clickError = false;
      try {
        await el.scrollIntoViewIfNeeded({ timeout: clickTimeoutMs }).catch(() => undefined);
        await el.click({ timeout: clickTimeoutMs });
      } catch {
        // A thrown click may still have navigated (destroyed context) — the
        // URL check below is the source of truth.
        clickError = true;
      }

      await settle(page, settleMs, deadline);
      const after = curUrl(page);
      const navigated = Boolean(after) && Boolean(before) && after !== before;

      // Click errored AND nothing changed → element was covered / not
      // actionable / detached. Count as a skip, not an interaction.
      if (clickError && !navigated) {
        stats.skippedOther++;
        continue;
      }

      stats.clicked++;
      globalBudget.remaining--;

      if (navigated) {
        // SPA pushState or a full navigation. The crawler's framenavigated /
        // request listeners already discovered it; publish the landing URL too
        // (same-origin), then restore so the rest of the queue still runs.
        if (sameOrigin(after, origin)) {
          stats.revealedAnchors += publishAnchors([after], "interaction-nav", pageUrl);
        }
        await restore(page, pageUrl, settleMs, deadline);
        continue;
      }

      // No navigation → a modal / accordion / menu / lazy render likely opened.
      // Re-harvest and re-enumerate to capture the freshly-revealed surface.
      try {
        const h = await harvestDom(page);
        stats.revealedAnchors += publishAnchors(h.anchors, "interaction-anchor", pageUrl);
        stats.revealedForms += publishForms(h.forms, "interaction-form", pageUrl);
      } catch {
        /* ignore harvest failure */
      }

      if (depth + 1 <= maxDepth) {
        try {
          for (const nc of await enumerateCandidates(page)) {
            if (!visited.has(nc.sig) && !queued.has(nc.sig)) {
              queued.add(nc.sig);
              work.push({ c: nc, depth: depth + 1 });
            }
          }
        } catch {
          /* ignore enumeration failure */
        }
      }
    } finally {
      await el.dispose().catch(() => undefined);
    }
  }

  stats.candidates = queued.size;
  if (log && stats.clicked > 0) {
    await log(
      "info",
      `interaction: ${stats.clicked} clicked / ${queued.size} candidate(s), ` +
        `${stats.skippedDestructive} destructive-skip, ${stats.skippedFormSubmit} form-submit-skip ` +
        `→ +${stats.revealedForms} form(s), +${stats.revealedAnchors} url(s) on ${pageUrl}`,
    );
  }
  return stats;
}

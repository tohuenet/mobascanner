/**
 * DiscoveryBus — per-scan pub/sub for URLs / forms / endpoints any scanner
 * surfaces while it runs.
 *
 * The static SiteMap (data/scans/<id>/sitemap.json) is a one-shot snapshot
 * the crawler writes when it finishes. The bus is the streaming analogue:
 * scanners call `ctx.discover(item)` whenever they encounter something new
 * (a 302 target after submitting a form, a JS-rendered URL, an XHR endpoint
 * captured in a browser tab) and downstream consumers re-process it.
 *
 * Three jobs:
 *   1. De-dupe — exact match on canonical key (URL + method, form shape).
 *   2. Page-class clustering — group `/user/1`, `/user/2`, `/user/3` into
 *      one class with a sample-cap. Without this a paginated site map blows
 *      the scan budget testing the same template N times.
 *   3. Drain detection — runner asks "are we settled?" so it knows when to
 *      transition out of the consumer phase.
 *
 * Foundation only (P1): bus exists, contract on ScanContext exposes it, but
 * no scanner publishes or consumes yet. Behavior identical to pre-bus.
 */

import type { SiteMapForm } from "../web/sitemap";

export type HttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD"
  | "OPTIONS";

/** Origin of a discovery — which scanner found it and through what mechanism.
 *  Helps debug "where did this URL come from" and lets consumers ignore items
 *  from themselves to avoid trivial loops. */
export interface ItemSource {
  scannerId: string;
  /** Short tag, e.g. "html-anchor" | "form-redirect" | "xhr-capture" | "js-mine". */
  via: string;
  /** Where the discovery surfaced (page URL, form action). */
  parentUrl?: string;
}

export type DiscoveredItem =
  | {
      kind: "url";
      url: string;
      method?: HttpMethod;
      source: ItemSource;
    }
  | {
      kind: "form";
      form: SiteMapForm;
      source: ItemSource;
    }
  | {
      kind: "endpoint";
      url: string;
      method: HttpMethod;
      /** Optional hint at the request body shape (e.g. for POST JSON). */
      bodyShape?: unknown;
      source: ItemSource;
    };

export interface DiscoveryBus {
  /** Publish an item. Returns true if it was new AND under the page-class
   *  sample cap — subscribers fire only in that case. Returns false for
   *  duplicates, capped classes, or when the bus has hit `maxItems`. */
  publish(item: DiscoveredItem): boolean;

  /** Subscribe to newly-published items. Returns an unsubscribe function. */
  subscribe(handler: (item: DiscoveredItem) => Promise<void> | void): () => void;

  /** Current items + class counts. Used by the runner to materialize a final
   *  SiteMap after the consumer phase ends. */
  snapshot(): BusSnapshot;

  /** Resolve when the bus has been quiet (no in-flight handlers, no new items)
   *  for `quietMs` consecutive milliseconds. Bounded by `budgetMs` from the
   *  call site so a pathological loop can't stall the scan forever. */
  drained(opts?: { quietMs?: number; budgetMs?: number }): Promise<{ timedOut: boolean }>;

  /** How many handlers are currently executing. Exposed for tests/diagnostics. */
  inFlight(): number;
}

export interface BusSnapshot {
  urls: Array<Extract<DiscoveredItem, { kind: "url" }>>;
  forms: SiteMapForm[];
  endpoints: Array<Extract<DiscoveredItem, { kind: "endpoint" }>>;
  /** Distinct page classes seen. */
  classCount: number;
  /** Items dropped because they hit the per-class sample cap. */
  clusterDropped: number;
  /** Items dropped because they hit `maxItems`. */
  overflowDropped: number;
}

export interface BusOptions {
  /** Hard cap on items kept (defensive — pathological loops). Default 5000. */
  maxItems?: number;
  /** How many representatives per page class to actually emit. The rest are
   *  recorded for dedupe but skipped by subscribers. Default 2. Tune higher
   *  for active scanners where different IDs yield different behavior (IDOR);
   *  lower for passive checks. */
  classSampleSize?: number;
}

/** Build the canonical-key for exact dedupe. Two items collide iff they're
 *  the "same request" — same URL (origin + path + sorted query keys, ignoring
 *  values) + method + form input set. */
export function canonicalKey(item: DiscoveredItem): string {
  if (item.kind === "form") {
    const inputs = item.form.inputs
      .map((i) => i.name)
      .filter(Boolean)
      .sort()
      .join(",");
    return `form|${item.form.method}|${canonicalUrl(item.form.action)}|${inputs}`;
  }
  const m = item.kind === "endpoint" ? item.method : (item.method ?? "GET");
  return `${item.kind}|${m}|${canonicalUrl(item.url)}`;
}

function canonicalUrl(u: string): string {
  try {
    const url = new URL(u);
    const sortedQ = [...url.searchParams.keys()].sort().join(",");
    return `${url.protocol}//${url.host}${url.pathname}?${sortedQ}`;
  } catch {
    return u;
  }
}

const NUM_SEG = /^[0-9]+$/;
const UUID_SEG = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Long alphanumeric chunks with at least one hyphen/digit — typical for
// SEO slugs, opaque ids, hashes. Picks up things like `1a2b3c4d5e6f` or
// `my-article-title-2024`.
const SLUG_SEG = /^[a-zA-Z0-9_-]{16,}$/;

/** Build the page-class key. Two URLs collide iff their path shapes match
 *  after replacing numeric / UUID / slug-looking segments with placeholders. */
export function pageClassKey(item: DiscoveredItem): string {
  const url = item.kind === "form" ? item.form.action : item.url;
  try {
    const u = new URL(url);
    const path = u.pathname
      .split("/")
      .map((seg) => {
        if (!seg) return seg;
        if (NUM_SEG.test(seg)) return "{n}";
        if (UUID_SEG.test(seg)) return "{uuid}";
        if (SLUG_SEG.test(seg)) return "{slug}";
        return seg;
      })
      .join("/");
    const sortedQ = [...u.searchParams.keys()].sort().join(",");
    const kind = item.kind === "form" ? `form|${item.form.method}` : item.kind;
    return `${kind}|${u.protocol}//${u.host}${path}?${sortedQ}`;
  } catch {
    return url;
  }
}

interface PageClass {
  /** Number of items the bus emitted (NOT counting capped ones). */
  emitted: number;
  /** Total members of the class — including those skipped past sample-cap. */
  total: number;
}

export function createDiscoveryBus(opts: BusOptions = {}): DiscoveryBus {
  const maxItems = opts.maxItems ?? 5000;
  const sampleCap = opts.classSampleSize ?? 2;

  const seen = new Set<string>();
  const classes = new Map<string, PageClass>();
  const items: DiscoveredItem[] = [];
  const handlers = new Set<(item: DiscoveredItem) => Promise<void> | void>();

  let inFlightCount = 0;
  /** Bumped every time publish() succeeds; drained() watches this to detect
   *  "did anything happen since I started waiting". */
  let publishCounter = 0;
  let clusterDropped = 0;
  let overflowDropped = 0;

  function dispatch(item: DiscoveredItem) {
    for (const h of handlers) {
      inFlightCount += 1;
      try {
        const r = h(item);
        if (r && typeof (r as Promise<void>).then === "function") {
          void (r as Promise<void>)
            .catch(() => {
              /* swallow — a misbehaving consumer shouldn't crash the scan */
            })
            .finally(() => {
              inFlightCount -= 1;
            });
        } else {
          inFlightCount -= 1;
        }
      } catch {
        inFlightCount -= 1;
      }
    }
  }

  function publish(item: DiscoveredItem): boolean {
    if (items.length >= maxItems) {
      overflowDropped += 1;
      return false;
    }
    const canon = canonicalKey(item);
    if (seen.has(canon)) return false;
    seen.add(canon);

    const cls = classes.get(pageClassKey(item)) ?? { emitted: 0, total: 0 };
    cls.total += 1;
    if (cls.emitted >= sampleCap) {
      classes.set(pageClassKey(item), cls);
      clusterDropped += 1;
      return false;
    }
    cls.emitted += 1;
    classes.set(pageClassKey(item), cls);

    items.push(item);
    publishCounter += 1;
    dispatch(item);
    return true;
  }

  function subscribe(handler: (item: DiscoveredItem) => Promise<void> | void) {
    handlers.add(handler);
    return () => {
      handlers.delete(handler);
    };
  }

  function snapshot(): BusSnapshot {
    const urls = items.filter(
      (i): i is Extract<DiscoveredItem, { kind: "url" }> => i.kind === "url",
    );
    const endpoints = items.filter(
      (i): i is Extract<DiscoveredItem, { kind: "endpoint" }> => i.kind === "endpoint",
    );
    const forms = items
      .filter((i): i is Extract<DiscoveredItem, { kind: "form" }> => i.kind === "form")
      .map((i) => i.form);
    return {
      urls,
      forms,
      endpoints,
      classCount: classes.size,
      clusterDropped,
      overflowDropped,
    };
  }

  async function drained(o?: { quietMs?: number; budgetMs?: number }): Promise<{ timedOut: boolean }> {
    const quietMs = o?.quietMs ?? 250;
    const budgetMs = o?.budgetMs ?? 10 * 60_000;
    const deadline = Date.now() + budgetMs;

    // Settle by two consecutive "quiet" snapshots: in-flight is zero AND no
    // publishes happened during `quietMs`. New publishes restart the wait.
    while (true) {
      if (Date.now() > deadline) return { timedOut: true };
      if (inFlightCount > 0) {
        await sleep(Math.min(50, quietMs));
        continue;
      }
      const counterBefore = publishCounter;
      await sleep(quietMs);
      if (inFlightCount === 0 && publishCounter === counterBefore) {
        return { timedOut: false };
      }
    }
  }

  function inFlight(): number {
    return inFlightCount;
  }

  return { publish, subscribe, snapshot, drained, inFlight };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

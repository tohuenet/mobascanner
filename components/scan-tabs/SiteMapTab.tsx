"use client";

/**
 * SiteMapTab — lazy-loaded view of `data/scans/<id>/sitemap.json` rendered as
 * a tree grouped by URL path segment. Lists discovered pages, forms, and API
 * hints (the data the crawler builds for every other web scanner to consume).
 *
 * Future hook for the dynamic-discovery work: subscribe to the "discovered"
 * SSE event and append to the tree in real time.
 */

import { useEffect, useState } from "react";
import { Chip, SeverityBadge, Skeleton } from "../ui/Primitives";
import type { SiteMap, SiteMapPage, SiteMapForm, SiteMapApiHint } from "@/lib/web/sitemap";

interface DiscoveredEvent {
  kind: "url" | "form" | "endpoint";
  url?: string;
  method?: string;
  source: { scannerId: string; via: string; parentUrl?: string };
  at: number;
}

export function SiteMapTab({
  scanId,
  discovered = [],
}: {
  scanId: string;
  /** Live items streamed in via SSE "discovered" events while a scan runs.
   *  Capped at 200 by the parent reducer. Shown above the static SiteMap. */
  discovered?: DiscoveredEvent[];
}) {
  const [state, setState] = useState<
    | { status: "loading" }
    | { status: "empty"; reason: string }
    | { status: "ready"; map: SiteMap }
    | { status: "error"; error: string }
  >({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch(`/api/scans/${scanId}/sitemap`);
        if (cancelled) return;
        if (r.status === 404) {
          setState({
            status: "empty",
            reason:
              "No site map for this scan. Enable web.crawler on the next scan to get one.",
          });
          return;
        }
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const map = (await r.json()) as SiteMap;
        if (!cancelled) setState({ status: "ready", map });
      } catch (e) {
        if (!cancelled)
          setState({
            status: "error",
            error: e instanceof Error ? e.message : String(e),
          });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  const liveSection = discovered.length > 0 ? <LiveDiscoveries items={discovered} /> : null;

  if (state.status === "loading") {
    return (
      <div className="grid gap-4">
        {liveSection}
        <div className="grid gap-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12" />
          ))}
        </div>
      </div>
    );
  }
  if (state.status === "empty") {
    return (
      <div className="grid gap-4">
        {liveSection}
        <div className="glass-thin p-10 text-center text-[color:var(--md-on-surface-variant)]">
          {state.reason}
        </div>
      </div>
    );
  }
  if (state.status === "error") {
    return (
      <div className="grid gap-4">
        {liveSection}
        <div className="glass p-4 flex items-center gap-2">
          <SeverityBadge severity="medium">error</SeverityBadge>
          <span>Failed to load site map: {state.error}</span>
        </div>
      </div>
    );
  }

  const map = state.map;
  const totals = {
    pages: map.pages.length,
    forms: map.forms.length,
    apis: map.apiHints.length,
    cookies: Object.keys(map.cookies ?? {}).length,
    tech: map.technologies.length,
  };

  return (
    <div className="flex flex-col gap-4">
      {liveSection}

      <div className="glass-thin p-3 flex flex-wrap items-center gap-3">
        <span className="md-label-l text-[color:var(--md-on-surface-variant)]">
          Site map for
        </span>
        <span className="mono md-body-m break-all flex-1 min-w-0">{map.origin}</span>
        <Chip className="!h-7">{totals.pages} pages</Chip>
        <Chip className="!h-7">{totals.forms} forms</Chip>
        <Chip className="!h-7">{totals.apis} API hints</Chip>
        <Chip className="!h-7">{totals.cookies} cookies</Chip>
        {totals.tech > 0 && (
          <Chip className="!h-7">{map.technologies.join(", ")}</Chip>
        )}
      </div>

      <Section title="Pages" count={map.pages.length}>
        {map.pages.length > 0 && <PagesTree pages={map.pages} origin={map.origin} />}
      </Section>

      <Section title="Forms" count={map.forms.length}>
        <div className="grid gap-2">
          {map.forms.map((f, i) => (
            <FormRow key={i} form={f} />
          ))}
        </div>
      </Section>

      <Section title="API hints" count={map.apiHints.length}>
        <div className="grid gap-1.5">
          {map.apiHints.map((h, i) => (
            <ApiHintRow key={i} hint={h} />
          ))}
        </div>
      </Section>
    </div>
  );
}

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  if (count === 0) return null;
  return (
    <details className="glass-thin p-3" open>
      <summary className="md-label-l cursor-pointer flex items-center gap-2">
        <span>{title}</span>
        <Chip className="!h-6 !px-2">{count}</Chip>
      </summary>
      <div className="mt-3">{children}</div>
    </details>
  );
}

function PagesTree({ pages, origin }: { pages: SiteMapPage[]; origin: string }) {
  // Group pages by first path segment so very wide site maps stay scannable.
  const groups = new Map<string, SiteMapPage[]>();
  for (const p of pages) {
    let key = "/";
    try {
      const u = new URL(p.url);
      const seg = u.pathname.split("/").filter(Boolean)[0];
      if (seg) key = "/" + seg;
    } catch {
      /* keep "/" */
    }
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(p);
  }
  const sorted = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);

  return (
    <div className="grid gap-2">
      {sorted.map(([prefix, items]) => (
        <details key={prefix} className="rounded-lg bg-[color-mix(in_oklab,var(--md-on-surface)_3%,transparent)] p-2">
          <summary className="cursor-pointer flex items-center gap-2 md-label-l">
            <span className="mono">{prefix}</span>
            <Chip className="!h-5 !px-1.5">{items.length}</Chip>
          </summary>
          <ul className="mt-2 grid gap-1">
            {items.slice(0, 200).map((p, i) => (
              <li key={i} className="flex items-center gap-2 md-body-s">
                <span
                  className="inline-grid place-items-center min-w-[3rem] h-5 px-1.5 rounded-full md-label-s"
                  style={{
                    background:
                      p.status >= 400
                        ? "color-mix(in oklab, var(--md-error) 18%, transparent)"
                        : p.status >= 300
                          ? "color-mix(in oklab, var(--md-severity-medium) 18%, transparent)"
                          : "color-mix(in oklab, var(--md-severity-low) 18%, transparent)",
                    color:
                      p.status >= 400
                        ? "var(--md-error)"
                        : p.status >= 300
                          ? "var(--md-severity-medium)"
                          : "var(--md-severity-low)",
                  }}
                >
                  {p.status}
                </span>
                <a
                  href={p.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mono break-all flex-1 hover:underline text-[color:var(--md-on-surface)]"
                >
                  {p.url.startsWith(origin) ? p.url.slice(origin.length) || "/" : p.url}
                </a>
                {p.interestScore !== undefined && p.interestScore >= 0.5 && (
                  <Chip className="!h-5 !px-1.5">★ {p.interestScore.toFixed(2)}</Chip>
                )}
              </li>
            ))}
            {items.length > 200 && (
              <li className="md-body-s text-[color:var(--md-on-surface-variant)]">
                …and {items.length - 200} more
              </li>
            )}
          </ul>
        </details>
      ))}
    </div>
  );
}

function FormRow({ form }: { form: SiteMapForm }) {
  return (
    <div className="rounded-lg bg-[color-mix(in_oklab,var(--md-on-surface)_3%,transparent)] p-2.5 flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <Chip className="!h-6 !px-2">{form.method}</Chip>
        <a
          href={form.action}
          target="_blank"
          rel="noopener noreferrer"
          className="mono md-body-s break-all flex-1 hover:underline"
        >
          {form.action}
        </a>
        {form.looksLikeLogin && <Chip className="!h-6 !px-2">login</Chip>}
        {form.hasCsrfToken && <Chip className="!h-6 !px-2">CSRF token</Chip>}
      </div>
      <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
        inputs: {form.inputs.map((i) => `${i.name}(${i.type})`).join(", ") || "(none)"}
      </span>
    </div>
  );
}

function LiveDiscoveries({ items }: { items: DiscoveredEvent[] }) {
  const urls = items.filter((i) => i.kind === "url").length;
  const forms = items.filter((i) => i.kind === "form").length;
  const endpoints = items.filter((i) => i.kind === "endpoint").length;
  return (
    <details className="glass p-3" open>
      <summary className="md-label-l cursor-pointer flex items-center gap-2 flex-wrap">
        <span
          aria-hidden
          className="inline-block w-2 h-2 rounded-full animate-pulse"
          style={{ background: "var(--md-severity-low)" }}
        />
        <span>Live discoveries</span>
        <Chip className="!h-6 !px-2">{urls} URLs</Chip>
        <Chip className="!h-6 !px-2">{forms} forms</Chip>
        <Chip className="!h-6 !px-2">{endpoints} endpoints</Chip>
        <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
          last {items.length} streamed via SSE
        </span>
      </summary>
      <ul className="grid gap-1 mt-3 max-h-72 overflow-auto">
        {items
          .slice()
          .reverse()
          .map((it, i) => (
            <li key={i} className="flex items-center gap-2 md-body-s">
              <Chip className="!h-5 !px-1.5">{it.kind}</Chip>
              {it.method && (
                <span className="md-label-s text-[color:var(--md-on-surface-variant)]">
                  {it.method}
                </span>
              )}
              <span className="mono break-all flex-1 min-w-0">{it.url ?? "(no url)"}</span>
              <span
                className="md-body-s text-[color:var(--md-on-surface-variant)] whitespace-nowrap"
                title={`from ${it.source.scannerId} via ${it.source.via}`}
              >
                {it.source.scannerId.replace(/^web\./, "")}/{it.source.via}
              </span>
            </li>
          ))}
      </ul>
    </details>
  );
}

function ApiHintRow({ hint }: { hint: SiteMapApiHint }) {
  return (
    <div className="flex items-center gap-2 md-body-s">
      <a
        href={hint.url}
        target="_blank"
        rel="noopener noreferrer"
        className="mono break-all flex-1 hover:underline text-[color:var(--md-on-surface)]"
      >
        {hint.url}
      </a>
      <span className="md-body-s text-[color:var(--md-on-surface-variant)]">
        from {hint.source}
      </span>
    </div>
  );
}

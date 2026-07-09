/**
 * Shared, dependency-free formatting helpers.
 *
 * Deliberately NOT a "use client" module: `relativeTime` is called from Server
 * Components (e.g. the dashboard and the scans list render it at request time)
 * as well as client code, so it must live in a plain module both sides can
 * import. Promoting it out of `app/page.tsx` (where it was a private copy) keeps
 * the dashboard, scans list, and any future surface rendering identical strings.
 */

/**
 * Compact relative time ("just now", "3m ago", "2d ago"). `now` is passed in so
 * the caller controls the reference clock — Server Components read the wall clock
 * once per request, avoiding client hydration drift.
 */
export function relativeTime(ts: number, now: number): string {
  const diff = now - ts;
  if (diff < 45_000) return "just now";
  const min = Math.floor(diff / 60_000);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 7) return `${day}d ago`;
  const wk = Math.floor(day / 7);
  if (wk < 5) return `${wk}w ago`;
  const mo = Math.floor(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(day / 365)}y ago`;
}

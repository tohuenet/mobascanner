/**
 * SiteMap — the shared "what this app actually contains" data structure
 * that the deep crawler builds and every other web scanner consumes.
 *
 * Without this, each scanner only ever probes the seed URL. With it, a
 * single crawl pass enumerates pages / forms / endpoints / cookies once,
 * and then headers / cors / jwt / fingerprint / active-injection / form-
 * fuzzer / verb-tampering all replay against the full surface.
 *
 * Persistence: the deep-crawler writes `data/scans/<scanId>/sitemap.json`.
 * Other scanners read it via `loadSiteMap(scanId)`. If it doesn't exist
 * (e.g. user disabled the crawler), the scanners fall back to the seed URL.
 */

import { promises as fs } from "node:fs";
import path from "node:path";

export interface SiteMapPage {
  url: string;
  method: "GET" | "POST" | "OPTIONS" | "HEAD" | "PUT" | "PATCH" | "DELETE";
  /** Status of the FIRST response — preserves redirect status (30x) if any. */
  status: number;
  /** Status of the final response (after redirect chain), if differs. */
  finalStatus?: number;
  /** Final URL after redirect chain. Equal to `url` when no redirect. */
  finalUrl?: string;
  contentType?: string;
  contentLength?: number;
  responseHeaders?: Record<string, string>;
  /** Set-Cookie values across all hops (may be multi-value). */
  setCookies?: string[];
  redirectChain?: string[];
  /** Reflective parameters discovered in the page. */
  reflectedQueryKeys?: string[];
  /** Score 0..1 indicating how likely this is an interesting endpoint. */
  interestScore?: number;
}

export interface SiteMapForm {
  /** URL the form was found on. */
  pageUrl: string;
  /** Resolved absolute URL of the form action. */
  action: string;
  method: "GET" | "POST";
  inputs: Array<{ name: string; type: string; value?: string; required?: boolean }>;
  /** Heuristic: is this likely a login form? */
  looksLikeLogin?: boolean;
  /** Heuristic: does this form already contain a CSRF-token-shaped input? */
  hasCsrfToken?: boolean;
}

export interface SiteMapApiHint {
  url: string;
  /** Where we found it — a script src, JSON, fetch() literal, etc. */
  source: string;
}

export interface SiteMap {
  scanId: string;
  origin: string;
  pages: SiteMapPage[];
  forms: SiteMapForm[];
  apiHints: SiteMapApiHint[];
  /** Cookies the server set during the crawl, by name. */
  cookies: Record<string, string>;
  /** Detected tech stack. */
  technologies: string[];
  /** When the map was built. */
  builtAt: number;
}

function siteMapPath(scanId: string): string {
  return path.join(process.cwd(), "data", "scans", scanId, "sitemap.json");
}

export async function saveSiteMap(map: SiteMap): Promise<void> {
  const file = siteMapPath(map.scanId);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(map, null, 2), "utf8");
}

export async function loadSiteMap(scanId: string): Promise<SiteMap | null> {
  try {
    const raw = await fs.readFile(siteMapPath(scanId), "utf8");
    return JSON.parse(raw) as SiteMap;
  } catch {
    return null;
  }
}

/** All unique URLs in the site map (pages + form actions + API hints). */
export function siteMapUrls(map: SiteMap): string[] {
  const set = new Set<string>();
  for (const p of map.pages) set.add(p.url);
  for (const f of map.forms) set.add(f.action);
  for (const a of map.apiHints) set.add(a.url);
  return [...set];
}

/** Pages whose interest score is above a threshold (worth deep-probing). */
export function interestingPages(map: SiteMap, min = 0.3): SiteMapPage[] {
  return map.pages.filter((p) => (p.interestScore ?? 0) >= min);
}

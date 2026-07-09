/**
 * BrowsingSession — a tiny cookie-jar + fetch wrapper that scanners share so
 * authenticated state persists across navigation.
 *
 * Why not use undici/CookieJar? Same-origin scope is fine here, and we want
 * full control over Set-Cookie tokens (we surface them as findings).
 */

import { rateLimitFor } from "./rate-limiter";
import { recordHttp } from "../engine/cost-tracker";
import { captureEntry } from "./traffic-capture";
import { getLiveSession } from "./session-defaults";

interface ParsedCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  expires?: number;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: string;
}

function parseSetCookie(raw: string): ParsedCookie | null {
  const parts = raw.split(";").map((s) => s.trim()).filter(Boolean);
  if (!parts.length) return null;
  const [nv, ...attrs] = parts;
  const eq = nv.indexOf("=");
  if (eq < 0) return null;
  const c: ParsedCookie = { name: nv.slice(0, eq), value: nv.slice(eq + 1) };
  for (const a of attrs) {
    const [kRaw, ...vParts] = a.split("=");
    const k = kRaw.toLowerCase();
    const v = vParts.join("=");
    if (k === "domain") c.domain = v;
    else if (k === "path") c.path = v;
    else if (k === "expires") c.expires = Date.parse(v);
    else if (k === "max-age") c.expires = Date.now() + Number(v) * 1000;
    else if (k === "secure") c.secure = true;
    else if (k === "httponly") c.httpOnly = true;
    else if (k === "samesite") c.sameSite = v;
  }
  return c;
}

export class BrowsingSession {
  readonly origin: string;
  private jar = new Map<string, ParsedCookie>();
  private extraHeaders: Record<string, string>;
  /** Track every Set-Cookie we ever observed (for the cookie scanner). */
  observedSetCookies: { url: string; raw: string }[] = [];
  /** History of redirects observed; useful for open-redirect scanner. */
  redirectHistory: { from: string; to: string }[] = [];

  constructor(origin: string, extraHeaders: Record<string, string> = {}) {
    this.origin = origin;
    // Live-browser mode: inherit the user's real Chrome session for this origin
    // — real User-Agent + spoofed client-hint headers, and seed the cookie jar
    // with the authenticated cookies so we don't look like an anonymous bot.
    // Caller-supplied extraHeaders win (explicit auth overrides).
    const live = getLiveSession(origin);
    if (live) {
      const liveHeaders: Record<string, string> = { ...(live.headers ?? {}) };
      if (live.userAgent) liveHeaders["User-Agent"] = live.userAgent;
      this.extraHeaders = { ...liveHeaders, ...extraHeaders };
      if (live.cookieHeader) this.seedCookies(live.cookieHeader);
    } else {
      this.extraHeaders = extraHeaders;
    }
  }

  /** Pre-populate the cookie jar from a `name=value; …` header string, so
   *  authenticated cookies persist across the whole crawl (a plain Cookie
   *  request header would get clobbered by the jar on the first response). */
  seedCookies(cookieHeader: string): void {
    for (const pair of cookieHeader.split(";")) {
      const s = pair.trim();
      if (!s) continue;
      const eq = s.indexOf("=");
      if (eq < 0) continue;
      const name = s.slice(0, eq).trim();
      const value = s.slice(eq + 1).trim();
      if (name) this.jar.set(name, { name, value });
    }
  }

  cookieHeader(): string {
    const live = [...this.jar.values()].filter((c) => !c.expires || c.expires > Date.now());
    return live.map((c) => `${c.name}=${c.value}`).join("; ");
  }

  cookies(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const c of this.jar.values()) out[c.name] = c.value;
    return out;
  }

  ingestSetCookie(rawValues: string[], pageUrl: string) {
    for (const raw of rawValues) {
      this.observedSetCookies.push({ url: pageUrl, raw });
      const c = parseSetCookie(raw);
      if (!c) continue;
      this.jar.set(c.name, c);
    }
  }

  /** fetch() that automatically threads cookies + custom headers. Manual
   *  redirects so we can inspect each hop. Returns the *final* response plus
   *  the FIRST hop's status + Location, which the open-redirect scanner needs. */
  async fetch(input: string | URL, init: RequestInit = {}): Promise<{
    res: Response;
    body: string;
    redirectChain: string[];
    finalUrl: string;
    /** Status of the very first response (may be 30x even if final is 200). */
    firstStatus: number;
    /** Location header of the first response, if it was a redirect. */
    firstLocation: string | null;
    /** All Set-Cookie values captured across hops. */
    allSetCookies: string[];
  }> {
    let url = typeof input === "string" ? input : input.toString();
    const redirectChain: string[] = [];
    const headers = new Headers(init.headers ?? {});
    for (const [k, v] of Object.entries(this.extraHeaders)) headers.set(k, v);
    if (!headers.has("User-Agent")) headers.set("User-Agent", "moba-scanner/0.1 (+session)");

    let firstStatus = 0;
    let firstLocation: string | null = null;
    const allSetCookies: string[] = [];

    for (let hop = 0; hop < 8; hop++) {
      const cookieStr = this.cookieHeader();
      if (cookieStr) headers.set("cookie", cookieStr);
      // Apply global politeness rate limit before every outbound request.
      await rateLimitFor(url);
      const t = Date.now();
      const res = await fetch(url, { ...init, headers, redirect: "manual" });
      const ms = Date.now() - t;
      const reqLen = (init.body ? String(init.body).length : 0) + url.length;
      recordHttp(0, reqLen, ms);
      // Capture for HAR export — fire-and-forget, never blocks.
      const reqHeaders: Record<string, string> = {};
      headers.forEach((v, k) => { reqHeaders[k] = v; });
      const resHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => { resHeaders[k] = v; });
      captureEntry(null, {
        startedAt: t, durationMs: ms,
        request: {
          method: (init.method ?? "GET").toUpperCase(),
          url, headers: reqHeaders,
          body: init.body ? String(init.body).slice(0, 8192) : undefined,
        },
        response: {
          status: res.status, statusText: res.statusText, headers: resHeaders,
          bodyLen: 0, // updated below after body read
          bodySnippet: "",
        },
      }).catch(() => {});

      type HeadersExt = Headers & { getSetCookie?: () => string[] };
      const ext = res.headers as HeadersExt;
      const setCookies = ext.getSetCookie ? ext.getSetCookie() : (res.headers.get("set-cookie")?.split(/,(?=[^;]+=)/) ?? []);
      if (setCookies.length) {
        this.ingestSetCookie(setCookies, url);
        allSetCookies.push(...setCookies);
      }

      if (hop === 0) {
        firstStatus = res.status;
        firstLocation = res.headers.get("location");
      }

      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("location");
        if (!loc) return { res, body: "", redirectChain, finalUrl: url, firstStatus, firstLocation, allSetCookies };
        const next = new URL(loc, url).toString();
        this.redirectHistory.push({ from: url, to: next });
        redirectChain.push(next);
        url = next;
        continue;
      }
      // Read body for any text-shaped content type — security scanners often
      // need to inspect XML / JSON / form / plain bodies, not just text/html.
      const ct = (res.headers.get("content-type") ?? "").toLowerCase();
      const isTextual = !ct ||
        ct.startsWith("text/") ||
        ct.includes("json") ||
        ct.includes("xml") ||
        ct.includes("javascript") ||
        ct.includes("ecmascript") ||
        ct.includes("x-www-form-urlencoded") ||
        ct.includes("yaml") ||
        ct.includes("toml");
      const body = isTextual ? await res.text() : "";
      return { res, body, redirectChain, finalUrl: url, firstStatus, firstLocation, allSetCookies };
    }
    return { res: new Response("", { status: 599 }), body: "", redirectChain, finalUrl: url, firstStatus, firstLocation, allSetCookies };
  }
}

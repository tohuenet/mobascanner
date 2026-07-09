/**
 * Per-origin "live session" defaults — the bridge that lets every fetch-based
 * scanner inherit the user's REAL browser session without touching the 23
 * places that construct a `BrowsingSession`.
 *
 * When live-browser mode is on (see `lib/web/browser.ts` / `live-session.ts`),
 * the runner captures the cookies + user-agent from the user's attached Chrome
 * once at scan start and registers them here keyed by origin. `BrowsingSession`
 * reads this in its constructor and:
 *   - sends the real browser's User-Agent (not `moba-scanner/0.1`, a bot tell),
 *   - seeds its cookie jar with the authenticated cookies.
 *
 * Result: requests look like they come from the logged-in human, so the
 * bot-detection / CAPTCHA walls that block the default crawler stand down.
 *
 * Global-by-origin (like `rate-limiter` / `traffic-capture`) — a scan runs in
 * one Node process and one origin, so there is no cross-talk in practice.
 */

export interface LiveSession {
  /** Serialized `name=value; name2=value2` cookie header for the origin. */
  cookieHeader: string;
  /** The real browser's navigator.userAgent, if captured. */
  userAgent?: string;
  /** Extra request headers to spoof (e.g. sec-ch-ua, Accept-Language). */
  headers?: Record<string, string>;
  /** When it was captured (ms) — informational. */
  capturedAt?: number;
}

declare global {
  var __mobaLiveSessions: Map<string, LiveSession> | undefined;
}
const store = (globalThis.__mobaLiveSessions ??= new Map<string, LiveSession>());

function originKey(origin: string): string {
  try { return new URL(origin).origin; } catch { return origin; }
}

export function setLiveSession(origin: string, session: LiveSession): void {
  store.set(originKey(origin), session);
}

export function getLiveSession(origin: string): LiveSession | undefined {
  return store.get(originKey(origin));
}

export function clearLiveSession(origin: string): void {
  store.delete(originKey(origin));
}

export function hasLiveSession(origin: string): boolean {
  return store.has(originKey(origin));
}

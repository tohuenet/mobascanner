/**
 * Capture the user's live browser session (cookies + user-agent) from an
 * attached Chrome, so the fetch-based scanners can impersonate the logged-in
 * human instead of a fresh anonymous bot.
 *
 * Called once by the runner at scan start when live-browser mode is on. The
 * result is registered via `setLiveSession(origin, …)` and picked up by every
 * `BrowsingSession` constructed afterwards.
 */

import { acquireBrowser, releaseBrowser, CHROME_CLIENT_HINTS, type AcquiredBrowser } from "./browser";
import type { LiveSession } from "./session-defaults";

/**
 * Connect to the configured CDP endpoint, read the cookies the browser would
 * send to `targetUrl` plus its real navigator.userAgent, and return a
 * `LiveSession`. Returns null if no endpoint is attached or capture fails.
 * Never closes the user's browser.
 */
export async function captureLiveSession(targetUrl: string, cdpUrl?: string | null): Promise<LiveSession | null> {
  let acq: AcquiredBrowser | null = null;
  try {
    acq = await acquireBrowser({ cdpUrl });
  } catch {
    return null; // can't reach the browser — caller logs a hint
  }
  if (!acq.attached) {
    // Only meaningful in attach mode; a freshly launched browser has no session.
    await releaseBrowser(acq, false);
    return null;
  }
  try {
    const context = acq.browser.contexts()[0];
    if (!context) return null;

    let cookieHeader = "";
    try {
      const cookies = await context.cookies(targetUrl);
      cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    } catch { /* fall through with empty */ }

    let userAgent: string | undefined;
    const pages = context.pages();
    try {
      if (pages.length > 0) {
        userAgent = await pages[0].evaluate(() => navigator.userAgent);
      } else {
        const p = await context.newPage();
        try { userAgent = await p.evaluate(() => navigator.userAgent); }
        finally { await p.close().catch(() => undefined); }
      }
    } catch { /* UA optional */ }

    if (!cookieHeader && !userAgent) return null;
    return { cookieHeader, userAgent, headers: CHROME_CLIENT_HINTS, capturedAt: Date.now() };
  } finally {
    // Leave the user's browser exactly as we found it.
    await releaseBrowser(acq, false).catch(() => undefined);
  }
}

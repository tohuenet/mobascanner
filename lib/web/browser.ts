/**
 * Browser provider — the single place that decides HOW we get a Chromium:
 *
 *   1. LIVE / ATTACH mode (preferred when configured): connect over the Chrome
 *      DevTools Protocol to a Chrome the USER is already running (real profile,
 *      real fingerprint, already logged in, CAPTCHAs already solved). This is
 *      the equivalent of "drive my real browser" — the tool borrows the user's
 *      session instead of looking like a fresh headless bot.
 *
 *   2. LAUNCH mode (fallback): spin up our own headless Chromium. We still send
 *      a realistic desktop-Chrome User-Agent (never `moba-scanner/0.1`, which is
 *      an instant bot tell) to reduce blocking.
 *
 * Enable live mode by launching Chrome with a debugging port and pointing the
 * tool at it:
 *
 *     chrome --remote-debugging-port=9222 --user-data-dir="%LOCALAPPDATA%\moba-chrome"
 *     set MOBA_BROWSER_CDP_URL=http://127.0.0.1:9222
 *
 * See docs/live-browser.md.
 */

import type { Browser, BrowserContext } from "playwright-core";

/** Playwright storageState shape (subset we produce from login profiles). */
export type StorageStateLike = {
  cookies?: Array<{ name: string; value: string; domain: string; path: string; expires?: number; httpOnly?: boolean; secure?: boolean; sameSite?: string }>;
  origins?: Array<{ origin: string; localStorage?: Array<{ name: string; value: string }> }>;
};

type NewContextOptions = NonNullable<Parameters<Browser["newContext"]>[0]>;

/** Realistic desktop Chrome UA for LAUNCH mode. Bump the major with Chrome. */
export const REALISTIC_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/** Client-hint headers a real Chrome sends; help pass basic bot checks. */
export const CHROME_CLIENT_HINTS: Record<string, string> = {
  "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
  "sec-ch-ua-mobile": "?0",
  "sec-ch-ua-platform": '"Windows"',
  "Accept-Language": "en-US,en;q=0.9",
};

let chromiumPromise: Promise<typeof import("playwright-core").chromium> | null = null;
async function getChromium() {
  if (!chromiumPromise) chromiumPromise = import("playwright-core").then((m) => m.chromium);
  return chromiumPromise;
}

/**
 * Launch args + init script that strip the automation "tells" bot-detection and
 * Google's sign-in flow look for. Without these, a Playwright browser sets
 * `navigator.webdriver=true` and the `--enable-automation` flag, and Google
 * refuses login with "This browser or app may not be secure" — the exact
 * failure the CDP/remote-debugging-port approach hits.
 */
const STEALTH_ARGS = [
  "--disable-blink-features=AutomationControlled",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-features=Translate,AutomationControlled,OptimizationHints",
  "--start-maximized",
];
const STEALTH_IGNORE_DEFAULT = ["--enable-automation", "--disable-component-extensions-with-background-pages"];
export const STEALTH_INIT_SCRIPT = `
  try {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    if (!window.chrome) window.chrome = { runtime: {} };
    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
    const q = window.navigator.permissions && window.navigator.permissions.query;
    if (q) window.navigator.permissions.query = (p) =>
      p && p.name === 'notifications'
        ? Promise.resolve({ state: (typeof Notification !== 'undefined' ? Notification.permission : 'default') })
        : q(p);
  } catch (e) { /* best effort */ }
`;

/**
 * Launch a REAL Chrome (falling back to bundled Chromium) with a PERSISTENT
 * profile directory and automation tells stripped. This is the login-and-scan
 * engine: because the profile persists and the browser looks human, the user
 * logs in ONCE (by hand — zero automation activity during login, so Google
 * accepts it) and every later scan reuses the same authenticated profile.
 *
 * Returns a BrowserContext (persistent contexts have no separate Browser). The
 * caller closes the context when done (which closes the window).
 */
export async function launchStealthPersistent(
  userDataDir: string,
  opts: { headless?: boolean; extraHeaders?: Record<string, string> } = {},
): Promise<{ context: BrowserContext; usedRealChrome: boolean }> {
  const chromium = await getChromium();
  const base = {
    headless: opts.headless ?? false,
    viewport: null,
    ignoreDefaultArgs: STEALTH_IGNORE_DEFAULT,
    args: STEALTH_ARGS,
    ignoreHTTPSErrors: true,
    // Keep Chrome's SANDBOX ON. Playwright defaults it off (--no-sandbox), which
    // pops the yellow "unsupported command-line flag" bar and is itself a strong
    // bot tell that CAPTCHA / Google sign-in key off.
    chromiumSandbox: true,
    ...(opts.extraHeaders ? { extraHTTPHeaders: opts.extraHeaders } : {}),
  } satisfies Parameters<typeof chromium.launchPersistentContext>[1];

  let context: BrowserContext;
  let usedRealChrome = true;
  try {
    // channel: "chrome" = the user's installed Google Chrome, not the bundled
    // Chromium — a far less suspicious fingerprint.
    context = await chromium.launchPersistentContext(userDataDir, { ...base, channel: "chrome" });
  } catch {
    // Fall back: bundled Chromium, and if the sandbox is what failed, without it.
    usedRealChrome = false;
    try {
      context = await chromium.launchPersistentContext(userDataDir, base);
    } catch {
      context = await chromium.launchPersistentContext(userDataDir, { ...base, chromiumSandbox: false });
    }
  }
  await context.addInitScript(STEALTH_INIT_SCRIPT);
  return { context, usedRealChrome };
}

declare global {
  var __mobaActiveCdp: string | undefined;
}

/** Set by the runner for the duration of a scan so the browser-based scanners
 *  (spa-crawler / dom-xss), which don't receive scan.meta, still see the same
 *  endpoint a per-scan `meta.browserCdpUrl` resolved to. */
export function setActiveCdpEndpoint(url: string | null): void {
  globalThis.__mobaActiveCdp = url ?? undefined;
}

/** The configured CDP endpoint for live mode, or null. Precedence: per-scan
 *  `meta.browserCdpUrl` → `MOBA_BROWSER_CDP_URL` env → the runner's active
 *  endpoint (so mid-scan browser scanners inherit a meta-only config). */
export function liveBrowserEndpoint(meta?: Record<string, unknown> | null): string | null {
  const fromMeta = meta && typeof meta.browserCdpUrl === "string" ? meta.browserCdpUrl : null;
  const url = (fromMeta || process.env.MOBA_BROWSER_CDP_URL || globalThis.__mobaActiveCdp || "").trim();
  return url || null;
}

export interface AcquiredBrowser {
  browser: Browser;
  /** True when we attached to an existing browser — callers must NOT close it,
   *  and should reuse its existing context (which already holds the session). */
  attached: boolean;
  endpoint: string | null;
}

/**
 * Get a Chromium: attach over CDP when an endpoint is configured, else launch.
 * Throws if playwright-core / the chromium binary is unavailable, or if a
 * configured endpoint can't be reached (so the caller can log a clear hint).
 */
export async function acquireBrowser(opts: {
  cdpUrl?: string | null;
  headless?: boolean;
} = {}): Promise<AcquiredBrowser> {
  const chromium = await getChromium();
  const endpoint = opts.cdpUrl ?? liveBrowserEndpoint();
  if (endpoint) {
    const browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });
    return { browser, attached: true, endpoint };
  }
  // Launch REAL Chrome with automation tells stripped when possible; fall back
  // to bundled Chromium. Even for scans (session already established), this
  // fingerprint is far less likely to trip mid-scan bot challenges.
  const launchOpts = {
    headless: opts.headless ?? true,
    args: STEALTH_ARGS,
    ignoreDefaultArgs: STEALTH_IGNORE_DEFAULT,
    chromiumSandbox: true, // no --no-sandbox tell
  };
  let browser: Browser;
  try {
    browser = await chromium.launch({ ...launchOpts, channel: "chrome" });
  } catch {
    try {
      browser = await chromium.launch(launchOpts);
    } catch {
      browser = await chromium.launch({ ...launchOpts, chromiumSandbox: false });
    }
  }
  return { browser, attached: false, endpoint: null };
}

/**
 * Get a usable context for crawling. In attach mode we REUSE the browser's
 * existing default context (it already carries the user's cookies / login); in
 * launch mode we create a fresh context with a realistic UA + optional
 * storageState. Returns the context plus whether it is owned (safe to close).
 */
export async function acquireContext(
  acq: AcquiredBrowser,
  opts: { userAgent?: string; storageState?: StorageStateLike; ignoreHTTPSErrors?: boolean; extraHeaders?: Record<string, string> } = {},
): Promise<{ context: BrowserContext; ownsContext: boolean }> {
  if (acq.attached) {
    const existing = acq.browser.contexts();
    if (existing.length > 0) return { context: existing[0], ownsContext: false };
    // Attached browser with no context yet — create one we own.
    const context = await acq.browser.newContext({ ignoreHTTPSErrors: opts.ignoreHTTPSErrors ?? true });
    return { context, ownsContext: true };
  }
  const contextOpts: NewContextOptions = {
    userAgent: opts.userAgent ?? REALISTIC_UA,
    ignoreHTTPSErrors: opts.ignoreHTTPSErrors ?? true,
    extraHTTPHeaders: { ...CHROME_CLIENT_HINTS, ...opts.extraHeaders },
  };
  if (opts.storageState) contextOpts.storageState = opts.storageState as NewContextOptions["storageState"];
  const context = await acq.browser.newContext(contextOpts);
  await context.addInitScript(STEALTH_INIT_SCRIPT);
  return { context, ownsContext: true };
}

/** Close what we own: never close an attached (user-owned) browser. */
export async function releaseBrowser(acq: AcquiredBrowser, ownsContext: boolean, context?: BrowserContext): Promise<void> {
  try {
    if (acq.attached) {
      if (ownsContext && context) await context.close().catch(() => undefined);
      // Leave the user's browser open.
      return;
    }
    await acq.browser.close().catch(() => undefined);
  } catch { /* ignore */ }
}

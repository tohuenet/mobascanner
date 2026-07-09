# Live-browser mode (drive your real Chrome)

By default the scanner crawls with Node `fetch` and a headless Chromium. On sites
with bot-detection (Cloudflare, DataDome, PerimeterX, hCaptcha/reCAPTCHA walls),
that traffic looks like a bot — no real cookies, a Node TLS fingerprint, and a
`moba-scanner/…` User-Agent — so you get CAPTCHA'd or blocked.

**Live-browser mode** attaches the scanner to **your own already-running Chrome**
over the Chrome DevTools Protocol (CDP). The tool then:

- reuses **your logged-in cookies** for every request (fetch-based scanners and
  the JS crawler alike),
- sends **your real browser's User-Agent** and client-hint headers,
- runs the SPA crawler and DOM-XSS probes **inside your real browser session**.

Because the requests come from a browser you already authenticated (and already
solved any CAPTCHA in), the walls that block the default crawler stand down.

## Setup (Windows)

1. **Close all Chrome windows** (a running Chrome without the debug flag won't
   expose the port). Then launch Chrome with a debugging port and a dedicated
   profile directory:

   ```bat
   "C:\Program Files\Google\Chrome\Application\chrome.exe" ^
     --remote-debugging-port=9222 ^
     --user-data-dir="%LOCALAPPDATA%\moba-chrome-profile"
   ```

   A dedicated `--user-data-dir` keeps this separate from your normal profile.
   The first time, log in to the target site(s) in this window and solve any
   CAPTCHA once.

2. **Point the tool at it** — set the endpoint before starting the app:

   ```bat
   set MOBA_BROWSER_CDP_URL=http://127.0.0.1:9222
   npm run dev
   ```

   (macOS/Linux: `export MOBA_BROWSER_CDP_URL=http://127.0.0.1:9222`.)

3. **Run a scan** against a target you're logged into in that Chrome window. The
   scan log shows:

   ```
   [live-browser] attached to http://127.0.0.1:9222 — reusing 14 cookie(s) + real User-Agent for https://target
   ```

That's it — every web scanner now rides your real session.

## Per-scan override

Instead of the env var, a scan can carry `meta.browserCdpUrl` (same value). Scan
meta takes precedence over the env var.

## Verifying the port

Open `http://127.0.0.1:9222/json/version` in any browser — you should see the
Chrome/CDP version JSON. If it doesn't load, Chrome wasn't started with
`--remote-debugging-port` (or another Chrome instance is holding the profile).

## Behaviour & safety

- The tool **never closes your browser** or your tabs — it only reads cookies and
  drives its own scanner pages/contexts. On teardown it closes only what it
  opened.
- If the endpoint is unreachable or the tab isn't logged in, the scan **logs a
  warning and falls back** to the normal anonymous crawl — it won't fail.
- Only scan targets you're authorized to test. Live mode uses YOUR authenticated
  session, so it acts as you.
- The captured cookies live in memory for the duration of the scan and are
  cleared when it finishes; they are not written to disk.

## Which parts use it

| Path | Uses live session |
|------|-------------------|
| `web.crawler`, `web.sqli`, `web.form-fuzzer`, and all other `fetch`-based scanners | Cookies + real UA via `BrowsingSession` |
| `web.spa-crawler`, `web.dom-xss` | Run inside the attached browser context |
| Recorder / captured-profile flow | Still available as a fallback when live mode is off |

## Fallback: captured session (no live browser)

If you can't run a debug-port Chrome, the existing **captured session** flow
(scan setup → Authentication → Captured session) records a login once and replays
its cookies. Live mode is strictly better against CAPTCHA walls, but the captured
profile still works for simple auth.

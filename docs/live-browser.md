# Using your real browser session (beat CAPTCHA / Google login)

By default the scanner crawls with Node `fetch` + a headless browser. On sites
with bot-detection (Cloudflare, DataDome, hCaptcha/reCAPTCHA) or Google/SSO
login, that traffic looks automated and gets CAPTCHA'd or blocked with
"This browser or app may not be secure."

There are two ways to run the scan as the logged-in human. **Prefer Captured
session** — it's the one that works with Google.

---

## ✅ Recommended: Captured session (works with Google / SSO)

Scan setup → **Authentication → Captured session → "Open browser to log in"**.

- Opens your **real Google Chrome** (not bundled Chromium) with the automation
  tells removed (`navigator.webdriver`, `--enable-automation`, the
  `--remote-debugging-port` flag are all absent) and a persistent profile.
- **You log in by hand** — Google, SSO, whatever. The tool performs *zero*
  automation during login, so there's nothing for Google's "not secure" check to
  detect. Solve any CAPTCHA once, as a human.
- Click **Save session**. Cookies + localStorage are snapshotted into the
  encrypted vault, and the Chrome profile persists under
  `data/browser-profiles/<name>/`.
- Pick that profile for the scan. Every scanner replays the authenticated
  session (fetch scanners get the cookies; the JS crawler gets cookies +
  localStorage, all with a real-Chrome fingerprint + stealth).

Why this works where the debug-port approach fails: Google blocks sign-in
whenever it detects remote debugging / automation flags. Here the login happens
in a browser with those tells stripped and **driven by you**, not the tool.

Requires Google Chrome installed and moba-scanner running locally (the window
opens on the same machine as the server).

---

## ⚠ Advanced: attach to a debug-port Chrome (does NOT work with Google login)

The `/scan/web` "Live browser" toggle attaches over CDP to a Chrome you launched
yourself:

```bat
chrome --remote-debugging-port=9222 --user-data-dir="%LOCALAPPDATA%\moba-chrome"
set MOBA_BROWSER_CDP_URL=http://127.0.0.1:9222   REM or use the toggle's endpoint field
```

Useful when you already have an authenticated debug Chrome (non-Google auth) and
want the scan to ride it. **The `--remote-debugging-port` flag trips Google's
automation block**, so you cannot sign in to Google in that window — log in via
Captured session instead. Precedence: per-scan `meta.browserCdpUrl` →
`MOBA_BROWSER_CDP_URL` env. The "Test connection" button reports whether the
attach works and how many cookies apply to the target.

---

## Safety

- The tool **never closes your browser or tabs** — it closes only what it opened.
- Captured cookies live in the encrypted vault; the persistent profile lives
  under the gitignored `data/` tree. Deleting a profile removes both.
- Only scan targets you're authorized to test — these modes act as *you*.
- If anything fails (no Chrome, endpoint unreachable, not logged in), the scan
  logs a warning and falls back to the anonymous crawl rather than failing.

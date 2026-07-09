# Using your real browser session (beat CAPTCHA / Google login)

By default the scanner crawls with Node `fetch` + a headless browser. On sites
with bot-detection (Cloudflare, DataDome, hCaptcha/reCAPTCHA) or Google/SSO
login, that traffic looks automated and gets CAPTCHA'd or blocked with
"This browser or app may not be secure."

There are three ways to run the scan as the logged-in human, from most to least
robust. **If you're fighting Google login or constant CAPTCHA, use the
extension** — it's the only path with *zero* automation, so there is literally
nothing for the site to detect, and it works with the app-bound cookie
encryption in Chrome 127+.

---

## ✅ Best: the companion extension (CAPTCHA-proof)

You log in **normally in your own Chrome** — no debug flags, no automation, no
`--no-sandbox` — so Google and bot-walls behave exactly as they do for you every
day. The extension then reads the resulting session via Chrome's trusted
`chrome.cookies` API and hands it to the scanner.

**Install once:**
1. Open `chrome://extensions`, turn on **Developer mode** (top-right).
2. **Load unpacked** → select the `extension/` folder in this repo.

**Use:**
1. In a normal tab, go to the target and **log in** (Google / SSO / whatever).
   Solve any CAPTCHA as yourself — it's your real browser.
2. Click the **moba-scanner** extension → **Capture my session + start scan**.
3. The scan starts with your real cookies **and** your real User-Agent + client
   hints, so its requests look like they came from the tab you're logged into.

Nothing about your browser is automated during login, so there is no
`navigator.webdriver`, no automation flag, no remote-debugging port — the exact
signals that trip the block are simply absent.

---

## ✅ Convenient: Captured session (real Chrome, log in once)

Scan setup → **Authentication → Captured session → "Open browser to log in"**.

Opens your **real Google Chrome** with the automation tells stripped
(`navigator.webdriver` gone, sandbox ON so there's no `--no-sandbox` infobar,
`--enable-automation` removed) and a persistent profile. You log in by hand; the
tool does nothing during login. Click **Save session**, pick the profile for the
scan.

This is Playwright-driven (it launches the window), so on the most aggressive
detectors it can still be caught where the extension would not. If Google login
fails here, use the extension.

---

## ⚠ Advanced: attach to a debug-port Chrome

The `/scan/web` "Live browser" toggle attaches over CDP to a Chrome you launched
with `--remote-debugging-port`. Only for a browser you're **already logged into
with non-Google auth** — the debug port trips Google's sign-in block. "Test
connection" reports the attach + cookie count.

---

## Safety

- The tool / extension **never closes your browser or tabs**.
- Captured cookies ride in the scan's auth headers (extension) or the encrypted
  vault (Captured session); persistent profiles live under the gitignored
  `data/` tree. Deleting a profile removes both.
- Only scan targets you're authorized to test — these modes act as *you*.
- If anything fails, the scan logs a warning and falls back to the anonymous
  crawl rather than failing.

## Still getting CAPTCHA after the extension?

A few sites fingerprint the TLS/JA3 handshake of every request, which differs
between Chrome and the scanner's HTTP client even with your cookies. Tell us the
host — the next step there is proxying the scanner's requests through the very
Chrome tab you're logged into, so even the TLS fingerprint matches.

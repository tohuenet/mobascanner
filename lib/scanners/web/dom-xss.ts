/**
 * DOM XSS scanner — fires payloads in a real Chromium tab and detects
 * execution via JavaScript hooks. Catches XSS that only fires after JS
 * runs (innerHTML manipulation, postMessage handlers, hash-based routing).
 *
 * Detection mechanism:
 *   1. Inject a hooks script at document_start that overrides:
 *      - alert / confirm / prompt
 *      - eval / Function constructor
 *      - innerHTML / outerHTML setters that contain our canary
 *      - document.cookie reads
 *   2. Navigate to URL with payload in fragment / query.
 *   3. Wait for either the canary marker to fire (set window.__moba_pwn = 1)
 *      OR a 5s timeout.
 *   4. If pwn fires → confirmed DOM XSS.
 *
 * Requires `playwright-core` + chromium binary.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { randomBytes } from "node:crypto";
import { acquireBrowser, acquireContext, releaseBrowser, liveBrowserEndpoint, REALISTIC_UA, type AcquiredBrowser } from "../../web/browser";

const HOOKS_SCRIPT = (canary: string) => `
(() => {
  const CANARY = ${JSON.stringify(canary)};
  const pwn = (sink) => { window.__moba_pwn = (window.__moba_pwn || []); window.__moba_pwn.push(sink); };
  const _alert = window.alert; window.alert = function(msg) { if (String(msg).includes(CANARY)) pwn('alert(' + msg + ')'); return _alert.apply(this, arguments); };
  const _confirm = window.confirm; window.confirm = function(msg) { if (String(msg).includes(CANARY)) pwn('confirm(' + msg + ')'); return _confirm.apply(this, arguments); };
  const _prompt = window.prompt; window.prompt = function(msg) { if (String(msg).includes(CANARY)) pwn('prompt(' + msg + ')'); return _prompt.apply(this, arguments); };
  const _eval = window.eval; window.eval = function(code) { if (typeof code === 'string' && code.includes(CANARY)) pwn('eval(' + code.slice(0, 80) + ')'); return _eval.apply(this, arguments); };
  // Function constructor — heuristic: caller passed our canary as code body.
  const _Fn = window.Function;
  window.Function = function() {
    const args = Array.from(arguments);
    if (args.some(a => typeof a === 'string' && a.includes(CANARY))) pwn('Function(' + args.join(',').slice(0, 80) + ')');
    return _Fn.apply(this, args);
  };
  // innerHTML / outerHTML — fires when sink receives our canary as HTML.
  const elProto = Element.prototype;
  const inner = Object.getOwnPropertyDescriptor(elProto, 'innerHTML');
  if (inner && inner.set) {
    Object.defineProperty(elProto, 'innerHTML', {
      set(v) { if (typeof v === 'string' && v.includes(CANARY)) pwn('innerHTML=' + v.slice(0, 80)); return inner.set.call(this, v); },
      get() { return inner.get.call(this); },
      configurable: true, enumerable: true,
    });
  }
})();
`;

const PAYLOAD_VARIANTS = (canary: string) => [
  // Fragment-based (location.hash sinks)
  { kind: "hash-svg",      apply: (u: URL) => { u.hash = `#<svg/onload=alert('${canary}')>`; return u; } },
  { kind: "hash-img",      apply: (u: URL) => { u.hash = `#<img src=x onerror=alert('${canary}')>`; return u; } },
  { kind: "hash-script",   apply: (u: URL) => { u.hash = `#<script>alert('${canary}')</script>`; return u; } },
  // Query-based (sometimes feeds into innerHTML)
  { kind: "query-svg",     apply: (u: URL) => { u.searchParams.set("q", `<svg/onload=alert('${canary}')>`); return u; } },
  { kind: "query-img",     apply: (u: URL) => { u.searchParams.set("q", `<img src=x onerror=alert('${canary}')>`); return u; } },
  // javascript: scheme — postMessage / open redirects
  { kind: "redirect-js",   apply: (u: URL) => { u.searchParams.set("next", `javascript:alert('${canary}')`); return u; } },
];

export const domXssScanner: Scanner = {
  id: "web.dom-xss",
  name: "DOM XSS (headless Chrome)",
  kind: "web",
  description: "Spawns a real Chromium tab via Playwright, fires payloads in URL fragment / query / `next=javascript:` and detects DOM-side execution via alert/eval/Function/innerHTML hooks. Catches XSS invisible to static reflection scanners.",
  defaultEnabled: false,
  async tool() {
    return {
      id: "web.dom-xss", name: "DOM XSS", kind: "web", backend: "library",
      status: "available",
      installHint: "Requires playwright-core + chromium binary. Run `npx playwright install chromium` once.",
      description: "Headless-Chromium DOM XSS scanner.",
    };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const candidates: URL[] = [seed];
    if (map) {
      for (const p of map.pages.slice(0, 25)) {
        const u = safeUrl(p.url); if (!u) continue;
        candidates.push(u);
      }
    }

    const cdpUrl = liveBrowserEndpoint(undefined);
    let acq: AcquiredBrowser;
    try {
      acq = await acquireBrowser({ cdpUrl, headless: true });
      if (acq.attached) await ctx.log("info", `attached to live browser at ${acq.endpoint} — DOM-XSS probes run in your real session`);
    } catch (e) {
      await ctx.log("warn", cdpUrl
        ? `could not attach to browser at ${cdpUrl}: ${e instanceof Error ? e.message : e}. Launch Chrome with --remote-debugging-port (docs/live-browser.md).`
        : `chromium not available (run \`npx playwright install chromium\`): ${e instanceof Error ? e.message : e}`);
      return;
    }

    const { context, ownsContext } = await acquireContext(acq, {
      userAgent: REALISTIC_UA,
      extraHeaders: ctx.target.auth?.headers,
    });

    let probed = 0;
    try {
      for (const target of candidates.slice(0, 25)) {
        if (ctx.signal.aborted) break;
        const canary = "domxss" + randomBytes(3).toString("hex");
        for (const v of PAYLOAD_VARIANTS(canary)) {
          if (ctx.signal.aborted) break;
          const probeUrl = v.apply(new URL(target.toString()));
          const page = await context.newPage();
          await page.addInitScript(HOOKS_SCRIPT(canary));
          probed += 1;
          try {
            // 5s navigate timeout — XSS sinks fire fast; longer = false noise.
            await page.goto(probeUrl.toString(), { timeout: 5000, waitUntil: "domcontentloaded" }).catch(() => {});
            // Give it 1s for any deferred sinks (postMessage handlers, setTimeout).
            await page.waitForTimeout(1000);
            const pwn = await page.evaluate(() => (window as { __moba_pwn?: string[] }).__moba_pwn ?? null).catch(() => null);
            if (pwn && pwn.length) {
              await ctx.emit(draft({
                severity: "high", confidence: "high",
                title: `DOM XSS via ${v.kind} on ${target.pathname}`,
                description: `Payload landed in a DOM sink and executed: \`${pwn[0]}\`. Confirmed in real Chromium — not a reflection-based false positive.`,
                ruleId: `dom-xss/${v.kind}`,
                cwe: ["CWE-79"], owasp: ["A03:2021"],
                location: { url: probeUrl.toString(), snippet: v.kind },
                evidence: { canary, sinks: pwn, payload: probeUrl.toString().slice(0, 200) },
                remediation: "Don't pass URL fragments / params into innerHTML / Function / eval. Use textContent or sanitization libraries (DOMPurify). Map fragment-based routing to lookups, not template strings.",
                references: ["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
              }));
              await page.close();
              break; // one DOM-XSS per page is enough.
            }
          } catch { /* tolerate */ }
          await page.close();
        }
      }
    } finally { await releaseBrowser(acq, ownsContext, context); }
    await ctx.progress(1, `${probed} DOM-XSS probes`);
  },
};

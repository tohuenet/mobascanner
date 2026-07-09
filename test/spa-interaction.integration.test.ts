/**
 * Integration test — the SPA interaction pass against a real click-only fixture.
 *
 * Turns the one-shot "does the DeepScan interaction engine actually reach
 * click-hidden state, and does it actually refuse destructive controls?" proof
 * into a durable regression test. It drives the REAL `runInteractionPass`
 * (lib/scanners/web/_interaction.ts) with a REAL Playwright/Chromium page over
 * a tiny local SPA whose surface is reachable ONLY through clicks:
 *
 *   - a button that innerHTML-injects a <form action="/api/contact"> (depth 0),
 *   - a nested button (revealed by that first click) that injects a second
 *     <form action="/api/details"> one interaction deeper (depth 1),
 *   - a button that history.pushState()s to /dashboard with NO <a href>, and
 *   - "Delete account" / "Log out" buttons whose click handlers would hit
 *     /danger/delete and /danger/logout — which the pass must NEVER trigger.
 *
 * If Chromium can't launch, the assertions are skipped (not failed) with a
 * reason, so the suite stays green on machines without the browser installed.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { chromium, type Browser } from "playwright-core";
import { runInteractionPass, type HarvestedForm } from "../lib/scanners/web/_interaction";

/** Click-only SPA: every interesting surface is hidden behind a click, so the
 *  navigation-only harvest can never see it — only the interaction pass can. */
const FIXTURE_HTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>click-only fixture</title></head>
<body>
<main>
  <h1>Fixture</h1>
  <button id="revealContact" type="button">Show contact form</button>
  <button id="goDashboard" type="button">Open dashboard</button>
  <button id="deleteAccount" type="button">Delete account</button>
  <button id="logOut" type="button">Log out</button>
  <div id="panel"></div>
</main>
<script>
  // (a) reveal a brand-new form only after a click (depth 0).
  document.getElementById('revealContact').addEventListener('click', function () {
    document.getElementById('panel').innerHTML =
      '<form action="/api/contact" method="POST">' +
        '<input name="email" type="email">' +
        '<input name="message" type="text">' +
        '<button type="submit">Send</button>' +
      '</form>' +
      '<button id="revealDetails" type="button">Show more options</button>';
  });
  // (c) a nested button (only present after (a)) reveals a SECOND form (depth 1).
  document.addEventListener('click', function (e) {
    var t = e.target;
    if (t && t.id === 'revealDetails') {
      var wrap = document.createElement('div');
      wrap.innerHTML =
        '<form action="/api/details" method="POST">' +
          '<input name="detail" type="text">' +
          '<button type="submit">Save details</button>' +
        '</form>';
      document.getElementById('panel').appendChild(wrap);
    }
  });
  // (b) an onClick-only SPA route push with NO <a href>.
  document.getElementById('goDashboard').addEventListener('click', function () {
    history.pushState({}, '', '/dashboard');
  });
  // (d) destructive controls — clicking either would hit the server; the pass
  //     must refuse them by their visible text, so these fetches never fire.
  document.getElementById('deleteAccount').addEventListener('click', function () {
    fetch('/danger/delete', { method: 'POST' });
  });
  document.getElementById('logOut').addEventListener('click', function () {
    fetch('/danger/logout', { method: 'POST' });
  });
</script>
</body>
</html>`;

describe("SPA interaction pass (real Chromium)", () => {
  let server!: http.Server;
  let base = "";
  let origin = "";
  let browser: Browser | undefined;
  let launchError = "";
  /** Every path the fixture server is asked for (reset at the start of each test). */
  const serverPaths: string[] = [];

  before(async () => {
    server = http.createServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      serverPaths.push(path);
      if (path === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(FIXTURE_HTML);
        return;
      }
      // Any other path (form targets, danger endpoints) → benign 200 so a
      // real navigation there resolves instead of erroring.
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end("<!doctype html><title>ok</title><p>ok</p>");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    origin = new URL(base).origin;
    try {
      browser = await chromium.launch({ headless: true });
    } catch (e) {
      launchError = e instanceof Error ? e.message : String(e);
    }
  });

  after(async () => {
    await browser?.close().catch(() => undefined);
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it(
    "default (non-aggressive): reaches click-hidden forms incl. depth-1, never fires destructive controls",
    { timeout: 30_000 },
    async (t) => {
      if (!browser) {
        t.skip(`Chromium unavailable: ${launchError}`);
        return;
      }
      serverPaths.length = 0;
      const publishedForms: HarvestedForm[] = [];
      const publishedAnchors: string[] = [];
      const context = await browser.newContext({ userAgent: "moba-scanner/test (+spa-interaction)" });
      const page = await context.newPage();
      try {
        await page.goto(base, { waitUntil: "domcontentloaded" });
        const startedAt = Date.now();
        const stats = await runInteractionPass({
          page,
          signal: new AbortController().signal,
          origin,
          pageUrl: base,
          aggressive: false,
          perPageBudget: 20,
          maxDepth: 2,
          globalBudget: { remaining: 50 },
          timeBudgetMs: 15_000,
          clickTimeoutMs: 2_000,
          settleMs: 500,
          publishAnchors: (anchors) => {
            publishedAnchors.push(...anchors);
            return anchors.length;
          },
          publishForms: (forms) => {
            publishedForms.push(...forms);
            return forms.length;
          },
        });
        const elapsed = Date.now() - startedAt;

        // (a) a click-revealed form was discovered (the nav-only harvest, which
        //     runs before any click, could never have seen it).
        assert.ok(
          publishedForms.some((f) => f.action.includes("/api/contact")),
          "click-revealed /api/contact form was published",
        );
        // (b) the depth-1 nested form (revealed by clicking a button that was
        //     itself only revealed by an earlier click) was discovered.
        assert.ok(
          publishedForms.some((f) => f.action.includes("/api/details")),
          "depth-1 nested /api/details form was discovered",
        );
        // (c) destructive controls were skipped by text and never actually clicked.
        assert.ok(!serverPaths.includes("/danger/delete"), "'/danger/delete' was never requested");
        assert.ok(!serverPaths.includes("/danger/logout"), "'/danger/logout' was never requested");
        assert.ok(
          stats.skippedDestructive >= 2,
          `>= 2 destructive candidates skipped (got ${stats.skippedDestructive})`,
        );
        // (d) bounded work, and terminated well within the time budget (no hang).
        assert.ok(stats.clicked <= 20, `clicked stayed within perPageBudget (got ${stats.clicked})`);
        assert.ok(elapsed < 25_000, `pass resolved within budget (took ${elapsed}ms)`);
        // bonus: the onClick-only pushState route (no <a href>) was published.
        assert.ok(
          publishedAnchors.some((a) => a.includes("/dashboard")),
          "onClick-only pushState route /dashboard was published",
        );
      } finally {
        await page.close().catch(() => undefined);
        await context.close().catch(() => undefined);
      }
    },
  );

  it(
    "aggressive: submits a revealed non-destructive form to /api/contact, still never fires destructive controls",
    { timeout: 30_000 },
    async (t) => {
      if (!browser) {
        t.skip(`Chromium unavailable: ${launchError}`);
        return;
      }
      serverPaths.length = 0;
      const context = await browser.newContext({ userAgent: "moba-scanner/test (+spa-interaction)" });
      const page = await context.newPage();
      try {
        await page.goto(base, { waitUntil: "domcontentloaded" });
        const stats = await runInteractionPass({
          page,
          signal: new AbortController().signal,
          origin,
          pageUrl: base,
          aggressive: true,
          perPageBudget: 20,
          maxDepth: 2,
          globalBudget: { remaining: 50 },
          timeBudgetMs: 15_000,
          clickTimeoutMs: 2_000,
          settleMs: 500,
          publishAnchors: (anchors) => anchors.length,
          publishForms: (forms) => forms.length,
        });

        // Aggressive mode DOES fire non-destructive form submitters: the revealed
        // contact form's submit reaches the server.
        assert.ok(serverPaths.includes("/api/contact"), "aggressive form submit reached /api/contact");
        // …but the destructive blocklist still holds, even under aggressive.
        assert.ok(!serverPaths.includes("/danger/delete"), "'/danger/delete' was never requested (aggressive)");
        assert.ok(!serverPaths.includes("/danger/logout"), "'/danger/logout' was never requested (aggressive)");
        assert.ok(
          stats.skippedDestructive >= 2,
          `>= 2 destructive candidates skipped (got ${stats.skippedDestructive})`,
        );
        assert.ok(stats.clicked <= 20, `clicked stayed within perPageBudget (got ${stats.clicked})`);
      } finally {
        await page.close().catch(() => undefined);
        await context.close().catch(() => undefined);
      }
    },
  );
});

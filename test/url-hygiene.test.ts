/**
 * URL-hygiene gate tests. Fixtures are the ACTUAL robots-pattern strings that
 * scan 4bb998fc (scribd.com) turned into a false-positive flood, plus the real
 * URLs that must still pass.
 */
import { test } from "node:test";
import assert from "node:assert";
import { isProbeableUrl, keepProbeableUrls, registrableDomain, sameSite } from "../lib/web/url-hygiene";

test("isProbeableUrl: rejects robots.txt match-patterns", () => {
  const patterns = [
    "https://scribd.com/*/followers",
    "https://scribd.com/*/following",
    "https://scribd.com/*/info$",
    "https://scribd.com/*/pingback$",
    "https://scribd.com/*/subscribers$",
    "https://scribd.com/*/d/",
    "https://scribd.com/*/friends$",
    "https://scribd.com/*/*/data$",
    "https://scribd.com/*?format=json",
    "https://scribd.com/blocks?",
    "https://scribd.com/api?",
    "https://scribd.com/book-preview/*/shadow_loader",
    "https://scribd.com/book-preview/*/recommenders",
  ];
  for (const p of patterns) {
    assert.strictEqual(isProbeableUrl(p), false, `expected pattern rejected: ${p}`);
  }
});

test("isProbeableUrl: accepts real fetchable URLs", () => {
  const real = [
    "https://scribd.com/",
    "https://scribd.com/analytics/",
    "https://scribd.com/archive/",
    "https://scribd.com/sitemap.xml",
    "https://scribd.com/api/",
    "https://scribd.com/search?q=hello",
    "https://scribd.com/doc/12345/Title",
    "http://example.com/a/b/c?x=1&y=2",
  ];
  for (const u of real) {
    assert.strictEqual(isProbeableUrl(u), true, `expected real URL accepted: ${u}`);
  }
});

test("isProbeableUrl: rejects non-http and malformed input", () => {
  for (const bad of ["", "not a url", "ftp://x.com/f", "javascript:alert(1)", "mailto:a@b.c", "//x.com/y"]) {
    assert.strictEqual(isProbeableUrl(bad), false, `expected rejected: ${bad}`);
  }
});

test("isProbeableUrl: encoded asterisk is allowed (only literal glob rejected)", () => {
  assert.strictEqual(isProbeableUrl("https://x.com/a%2Ab"), true);
  assert.strictEqual(isProbeableUrl("https://x.com/a*b"), false);
});

test("registrableDomain / sameSite: own-CDN subdomains are first-party", () => {
  assert.strictEqual(registrableDomain("www.scribd.com"), "scribd.com");
  assert.strictEqual(registrableDomain("assets.production.scribd.com"), "scribd.com");
  assert.strictEqual(registrableDomain("foo.example.co.uk"), "example.co.uk");
  // A site's own CDN subdomain is same-site (must NOT be flagged as 3rd-party SRI).
  assert.strictEqual(sameSite("assets.production.scribd.com", "www.scribd.com"), true);
  assert.strictEqual(sameSite("cdn.example.com", "www.example.com"), true);
  // A genuinely different site is not same-site.
  assert.strictEqual(sameSite("evil-cdn.net", "www.example.com"), false);
  assert.strictEqual(sameSite("example.net", "example.com"), false);
});

test("keepProbeableUrls: filters and de-dupes preserving order", () => {
  const out = keepProbeableUrls([
    "https://x.com/a",
    "https://x.com/*/b",
    "https://x.com/a", // dup
    "https://x.com/c?d=1",
  ]);
  assert.deepStrictEqual(out, ["https://x.com/a", "https://x.com/c?d=1"]);
});

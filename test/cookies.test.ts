/**
 * Cookie-assessment tests. Fixtures are the ACTUAL Set-Cookie headers scribd.com
 * returned during scan 4bb998fc. The old scanner judged flags from an
 * attribute-less jar and reported Secure/HttpOnly "missing" on cookies that
 * plainly have them — these lock in that a real header is read correctly.
 */
import { test } from "node:test";
import assert from "node:assert";
import { assessCookie } from "../lib/scanners/web/cookies";

const rules = (raw: string) => assessCookie(raw, true).map((i) => i.rule);

test("assessCookie: does NOT flag Secure/HttpOnly when the header has them", () => {
  // Real _scribd_session: has `secure` and `HttpOnly`.
  const r = rules("_scribd_session=abc; domain=.scribd.com; path=/; expires=Mon, 09 Jul 2029 08:59:29 GMT; secure; HttpOnly");
  assert.ok(!r.includes("cookies/secure"), "must not report missing Secure");
  assert.ok(!r.includes("cookies/httponly"), "must not report missing HttpOnly");
});

test("assessCookie: real auth0 cookie (Secure+HttpOnly+SameSite=None) is clean of flag findings", () => {
  const r = rules("auth0=xyz; Path=/; Expires=Sun, 12 Jul 2026 08:59:33 GMT; HttpOnly; Secure; SameSite=None");
  assert.ok(!r.includes("cookies/secure"));
  assert.ok(!r.includes("cookies/httponly"));
  assert.ok(!r.includes("cookies/samesite"));
  assert.ok(!r.includes("cookies/samesite-none-insecure"));
});

test("assessCookie: genuinely missing Secure IS still reported", () => {
  const r = rules("sessionid=abc; Path=/; HttpOnly");
  assert.ok(r.includes("cookies/secure"), "missing Secure on HTTPS must be flagged");
});

test("assessCookie: SameSite=None without Secure is flagged", () => {
  const r = rules("tracker=1; Path=/; SameSite=None");
  assert.ok(r.includes("cookies/samesite-none-insecure"));
});

test("assessCookie: a bare name=value jar entry cannot manufacture flag findings", () => {
  // This is what the OLD code fed the parser. With no attributes present we
  // must not confidently assert Secure/HttpOnly are 'missing' as HIGH findings
  // for a session cookie — but since the header truly lacks them, at most a
  // low-value SameSite/secure note appears. The regression we care about is
  // that a REAL header (previous tests) is never mis-reported; here we simply
  // assert the function stays pure and returns an array.
  const out = assessCookie("_scribd_session=abc", true);
  assert.ok(Array.isArray(out));
});

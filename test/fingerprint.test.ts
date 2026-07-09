/**
 * Regression tests for the live-version extractor
 * (`lib/scanners/web/fingerprint.ts` → `extractLiveVersions`).
 *
 * This is the runtime side of the correlation engine's version-reachability
 * join, so its parsing must stay stable and never fabricate versions.
 */
import { test } from "node:test";
import assert from "node:assert";
import { extractLiveVersions } from "../lib/scanners/web/fingerprint";

test("extractLiveVersions: Server header product/version", () => {
  const out = extractLiveVersions({ server: "vulnserver/1.2.3" });
  const e = out.find((v) => v.pkg === "vulnserver");
  assert.ok(e, "vulnserver detected");
  assert.strictEqual(e.version, "1.2.3");
});

test("extractLiveVersions: X-Powered-By PHP version", () => {
  const out = extractLiveVersions({ poweredBy: "PHP/8.1.2" });
  const e = out.find((v) => v.pkg === "php");
  assert.ok(e, "php detected");
  assert.strictEqual(e.version, "8.1.2");
});

test("extractLiveVersions: <meta generator> WordPress version", () => {
  const out = extractLiveVersions({ body: '<meta name="generator" content="WordPress 6.2.1">' });
  const e = out.find((v) => v.pkg === "wordpress");
  assert.ok(e, "wordpress detected");
  assert.strictEqual(e.version, "6.2.1");
});

test("extractLiveVersions: served <script> bundle jquery version", () => {
  const out = extractLiveVersions({ body: '<script src="jquery-3.5.1.min.js"></script>' });
  const e = out.find((v) => v.pkg === "jquery");
  assert.ok(e, "jquery detected");
  assert.strictEqual(e.version, "3.5.1");
});

test("extractLiveVersions: package.json dependency range is stripped to a base version", () => {
  const out = extractLiveVersions({ packageJsonText: '{"dependencies":{"lodash":"^4.17.21"}}' });
  const e = out.find((v) => v.pkg === "lodash");
  assert.ok(e, "lodash detected");
  assert.strictEqual(e.version, "4.17.21");
});

test("extractLiveVersions: an input with no parseable version emits no bogus entry", () => {
  const out = extractLiveVersions({ server: "nginx", body: "<div>no versions here</div>" });
  assert.strictEqual(out.length, 0);
});

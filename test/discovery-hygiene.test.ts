/**
 * DiscoveryBus hygiene: the bus must reject synthetic/pattern URLs at publish
 * so no consumer ever fetches a robots glob and mistakes its unstable response
 * for a vulnerability.
 */
import { test } from "node:test";
import assert from "node:assert";
import { createDiscoveryBus } from "../lib/engine/discovery";

test("bus.publish drops robots-pattern URLs and keeps real ones", () => {
  const bus = createDiscoveryBus({ classSampleSize: 100 });
  const src = { scannerId: "web.crawler", via: "test" };

  assert.strictEqual(bus.publish({ kind: "url", url: "https://x.com/*?format=json", source: src }), false);
  assert.strictEqual(bus.publish({ kind: "url", url: "https://x.com/blocks?", source: src }), false);
  assert.strictEqual(bus.publish({ kind: "url", url: "https://x.com/*/followers", source: src }), false);
  assert.strictEqual(bus.publish({ kind: "url", url: "https://x.com/real/path", source: src }), true);
  assert.strictEqual(bus.publish({ kind: "url", url: "https://x.com/search?q=1", source: src }), true);

  const snap = bus.snapshot();
  assert.strictEqual(snap.urls.length, 2, "only the two real URLs survive");
});

test("bus.publish validates form action URLs too", () => {
  const bus = createDiscoveryBus({ classSampleSize: 100 });
  const src = { scannerId: "web.crawler", via: "test" };
  const form = { pageUrl: "https://x.com/", method: "POST" as const, inputs: [{ name: "q", type: "text" }] };
  assert.strictEqual(bus.publish({ kind: "form", form: { ...form, action: "https://x.com/*/submit" }, source: src }), false);
  assert.strictEqual(bus.publish({ kind: "form", form: { ...form, action: "https://x.com/submit" }, source: src }), true);
});

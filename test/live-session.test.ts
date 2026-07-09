/**
 * Live-browser session bridge: when a live session is registered for an origin,
 * every BrowsingSession for that origin must send the real browser's cookies +
 * User-Agent over the wire (so we stop looking like an anonymous bot). Uses a
 * local echo server to assert the actual request headers.
 */
import { test } from "node:test";
import assert from "node:assert";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { BrowsingSession } from "../lib/web/session";
import { setLiveSession, clearLiveSession, getLiveSession } from "../lib/web/session-defaults";

async function echoServer(): Promise<{ origin: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ua: req.headers["user-agent"] ?? "", cookie: req.headers["cookie"] ?? "" }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { origin, close: () => new Promise<void>((r) => server.close(() => r())) };
}

test("BrowsingSession inherits the live session's cookies + real User-Agent", async () => {
  const { origin, close } = await echoServer();
  try {
    setLiveSession(origin, { cookieHeader: "sid=abc123; theme=dark", userAgent: "Mozilla/5.0 RealChrome/131" });
    const s = new BrowsingSession(origin);
    const r = await s.fetch(origin + "/");
    const body = JSON.parse(r.body);
    assert.strictEqual(body.ua, "Mozilla/5.0 RealChrome/131", "real UA sent, not moba-scanner");
    assert.match(body.cookie, /sid=abc123/);
    assert.match(body.cookie, /theme=dark/);
  } finally {
    clearLiveSession(origin);
    await close();
  }
});

test("without a live session, the default UA is used and no cookies are seeded", async () => {
  const { origin, close } = await echoServer();
  try {
    const s = new BrowsingSession(origin);
    const r = await s.fetch(origin + "/");
    const body = JSON.parse(r.body);
    assert.match(body.ua, /moba-scanner/, "falls back to default UA");
    assert.strictEqual(body.cookie, "");
  } finally {
    await close();
  }
});

test("seedCookies populates the jar; clearLiveSession removes the registration", () => {
  const origin = "http://seed.test";
  setLiveSession(origin, { cookieHeader: "x=1; y=2" });
  assert.ok(getLiveSession(origin));
  const s = new BrowsingSession(origin);
  assert.strictEqual(s.cookies().x, "1");
  assert.strictEqual(s.cookies().y, "2");
  clearLiveSession(origin);
  assert.strictEqual(getLiveSession(origin), undefined);
});

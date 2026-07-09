/**
 * Integration test — the live-version extractor against the real vulnerable target.
 *
 * Spins up scripts/vuln-target.mjs (the repo's intentionally-vulnerable server,
 * which advertises `Server: vulnserver/1.2.3` + `X-Powered-By: Express`) on a
 * free port, fetches its root over a real socket, and feeds the REAL response
 * headers + body into the REAL `extractLiveVersions`
 * (lib/scanners/web/fingerprint.ts). This promotes the "does the extractor pull
 * concrete versions off a live server?" check into a durable end-to-end
 * regression test — real headers, real bytes — not just a string-fixture unit test.
 *
 * If a port can't be bound / the child can't start, the test is skipped (not
 * failed) with a reason.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { spawn } from "node:child_process";
import net, { type AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { extractLiveVersions } from "../lib/scanners/web/fingerprint";

/** Ask the OS for a currently-free TCP port, then release it for the child. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

/** Poll the root until the server answers or the deadline passes. */
async function waitForServer(url: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      await resp.arrayBuffer().catch(() => undefined);
      return true;
    } catch {
      await new Promise((done) => setTimeout(done, 150));
    }
  }
  return false;
}

describe("fingerprint live-version extraction (real vuln-target)", () => {
  it(
    "extracts vulnserver@1.2.3 + express from the running server's real headers",
    { timeout: 30_000 },
    async (t) => {
      let port: number;
      try {
        port = await freePort();
      } catch (e) {
        t.skip(`could not bind a local port: ${e instanceof Error ? e.message : String(e)}`);
        return;
      }

      const script = fileURLToPath(new URL("../scripts/vuln-target.mjs", import.meta.url));
      const child = spawn(process.execPath, [script], {
        env: { ...process.env, PORT: String(port) },
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr?.on("data", (d: Buffer) => {
        stderr += d.toString();
      });
      let spawnError = "";
      child.on("error", (e) => {
        spawnError = e.message;
      });

      try {
        const base = `http://127.0.0.1:${port}/`;
        const up = await waitForServer(base, 8_000);
        if (!up) {
          const detail = [
            spawnError && `spawn error: ${spawnError}`,
            stderr && `stderr: ${stderr.slice(0, 200)}`,
          ]
            .filter(Boolean)
            .join("; ");
          t.skip(`vuln-target did not come up on port ${port}${detail ? ` (${detail})` : ""}`);
          return;
        }

        const res = await fetch(base);
        const live = extractLiveVersions({
          server: res.headers.get("server"),
          poweredBy: res.headers.get("x-powered-by"),
          body: await res.text(),
        });

        // From `Server: vulnserver/1.2.3` — a precise, CVE-lookupable version.
        const vulnserver = live.find((v) => v.pkg === "vulnserver");
        assert.ok(vulnserver, "vulnserver detected from the live Server header");
        assert.strictEqual(vulnserver.version, "1.2.3", "vulnserver version parsed from the Server header");
        assert.strictEqual(vulnserver.source, "header");

        // From `X-Powered-By: Express` — name-only, but the presence itself is a
        // reliable framework signal the correlation engine relies on.
        const express = live.find((v) => v.pkg === "express");
        assert.ok(express, "express detected from the live X-Powered-By header");
        assert.strictEqual(express.source, "header");
      } finally {
        child.kill();
      }
    },
  );
});

/**
 * MITM proxy mode — DESIGN STUB + minimal HTTP-only proxy.
 *
 * Why a stub: a real TLS-MITM proxy needs:
 *   1. A per-user CA + per-host on-the-fly leaf cert generation (`mockttp` or
 *      a custom `tls.SecureContext` factory).
 *   2. The user installs the CA cert as a system trust root.
 *   3. Browser → http://localhost:8888 → MITM → real upstream.
 *
 * For this commit we ship:
 *   - A working *plain HTTP* CONNECT-ignoring proxy (`startHttpProxy(port)`).
 *   - Every request/response captured into the active scan's HAR
 *     (so user-driven browsing fills the SiteMap automatically).
 *   - For TLS, the proxy 502s with an instructive message. Full TLS-MITM
 *     lands when we add `mockttp` as a dep.
 *
 * Use-cases this UNLOCKS even in HTTP-only mode:
 *   - Internal HTTP services (no TLS) where the team wants quick capture.
 *   - Test rigs where http://localhost is OK.
 *   - As a bridge: user runs `mitmproxy --mode upstream:http://localhost:8888`,
 *     and our HTTP proxy fans out to mitmproxy's TLS handling.
 */

import http from "node:http";
import { captureEntry } from "../web/traffic-capture";

let server: http.Server | null = null;

export interface ProxyOptions {
  port: number;
  /** Hard-cap captured body size to avoid OOM. */
  maxBodyBytes?: number;
}

export function startHttpProxy(opts: ProxyOptions): { stop: () => void } {
  if (server) throw new Error("proxy already running");
  const max = opts.maxBodyBytes ?? 64 * 1024;
  server = http.createServer((clientReq, clientRes) => {
    const url = new URL(clientReq.url ?? "/", `http://${clientReq.headers.host ?? "localhost"}`);
    if (url.protocol !== "http:") {
      clientRes.statusCode = 502;
      clientRes.end("moba-scanner mitm proxy supports plain HTTP only — install mockttp for TLS-MITM");
      return;
    }
    const startedAt = Date.now();
    const reqHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(clientReq.headers)) {
      if (typeof v === "string") reqHeaders[k] = v;
      else if (Array.isArray(v)) reqHeaders[k] = v.join(", ");
    }
    const reqChunks: Buffer[] = [];
    let reqBytes = 0;
    clientReq.on("data", (c: Buffer) => { reqBytes += c.length; if (reqBytes <= max) reqChunks.push(c); });
    clientReq.on("end", () => {
      const reqBody = Buffer.concat(reqChunks).toString("utf8");
      const upstream = http.request({
        method: clientReq.method,
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname + url.search,
        headers: reqHeaders,
      }, (upstreamRes) => {
        const resHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(upstreamRes.headers)) {
          if (typeof v === "string") resHeaders[k] = v;
          else if (Array.isArray(v)) resHeaders[k] = v.join(", ");
        }
        clientRes.writeHead(upstreamRes.statusCode ?? 200, upstreamRes.statusMessage, upstreamRes.headers);
        const resChunks: Buffer[] = [];
        let resBytes = 0;
        upstreamRes.on("data", (c: Buffer) => {
          resBytes += c.length;
          if (resBytes <= max) resChunks.push(c);
          clientRes.write(c);
        });
        upstreamRes.on("end", () => {
          clientRes.end();
          const resBody = Buffer.concat(resChunks).toString("utf8");
          captureEntry("mitm-proxy", {
            startedAt, durationMs: Date.now() - startedAt,
            request: { method: clientReq.method ?? "GET", url: url.toString(), headers: reqHeaders, body: reqBody.slice(0, 8192) },
            response: { status: upstreamRes.statusCode ?? 0, statusText: upstreamRes.statusMessage ?? "", headers: resHeaders, bodyLen: resBytes, bodySnippet: resBody.slice(0, 4096) },
          }).catch(() => {});
        });
      });
      upstream.on("error", (e) => {
        clientRes.writeHead(502, "Bad Gateway");
        clientRes.end(String(e));
      });
      if (reqBytes > 0) upstream.write(Buffer.concat(reqChunks));
      upstream.end();
    });
  });
  server.listen(opts.port);
  return {
    stop: () => { server?.close(); server = null; },
  };
}

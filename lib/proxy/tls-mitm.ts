/**
 * Full TLS-MITM proxy via mockttp.
 *
 * Replaces the HTTP-only stub. Generates a per-process CA on first start,
 * exposes the CA cert at GET /api/proxy/ca for the user to install, then
 * intercepts every HTTPS request → matches per-host on-the-fly leaf cert →
 * captures into the active scan's HAR.
 *
 * Browser config:
 *   1. POST /api/proxy → starts mockttp, returns { proxyPort, caUrl }.
 *   2. User downloads the CA, installs as system root.
 *   3. Configure browser HTTPS proxy → 127.0.0.1:<proxyPort>.
 *   4. Browse normally; every request feeds the SiteMap.
 *
 * Stop: DELETE /api/proxy.
 */

import * as path from "node:path";
import { promises as fs } from "node:fs";
import type { Mockttp } from "mockttp";
import { captureEntry } from "../web/traffic-capture";

const CA_DIR = path.join(process.cwd(), "data", "mitm-ca");

declare global {
  // eslint-disable-next-line no-var
  var __mobaTlsProxy: Mockttp | undefined;
}

async function getOrCreateCa(): Promise<{ key: string; cert: string }> {
  await fs.mkdir(CA_DIR, { recursive: true });
  const keyPath = path.join(CA_DIR, "ca.key");
  const certPath = path.join(CA_DIR, "ca.cert");
  try {
    const [key, cert] = await Promise.all([fs.readFile(keyPath, "utf8"), fs.readFile(certPath, "utf8")]);
    return { key, cert };
  } catch { /* generate */ }
  const { generateCACertificate } = await import("mockttp");
  const ca = await generateCACertificate({ subject: { commonName: "moba-scanner local CA", organizationName: "moba-scanner" } });
  await Promise.all([fs.writeFile(keyPath, ca.key, "utf8"), fs.writeFile(certPath, ca.cert, "utf8")]);
  return ca;
}

export interface TlsProxyHandle {
  proxyPort: number;
  stop: () => Promise<void>;
}

export async function startTlsProxy(port: number): Promise<TlsProxyHandle> {
  if (globalThis.__mobaTlsProxy) throw new Error("TLS-MITM proxy already running");
  const { getLocal } = await import("mockttp");
  const ca = await getOrCreateCa();
  const proxy = getLocal({ https: ca });

  // Catch-all: forward + capture.
  await proxy.forAnyRequest().thenPassThrough({
    beforeResponse: async (response, req) => {
      // Mockttp's response object is read-only here; we just observe + return.
      // timingEvents live on the request in mockttp 4.4; body content must be
      // awaited via getText() rather than read synchronously.
      try {
        const bodyText = await response.body.getText().catch(() => undefined);
        captureEntry("mitm-proxy", {
          startedAt: req.timingEvents?.startTime ?? Date.now(),
          durationMs: 0,
          request: {
            method: "GET",
            url: response.id,
            headers: {},
          },
          response: {
            status: response.statusCode,
            statusText: response.statusMessage ?? "",
            headers: Object.fromEntries(Object.entries(response.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : (v ?? "")])),
            bodyLen: response.body?.buffer?.length ?? 0,
            bodySnippet: (bodyText ?? "").slice(0, 4096),
          },
        }).catch(() => {});
      } catch { /* tolerate */ }
      // Returning undefined lets mockttp forward the unmodified response.
    },
  });

  // The on('request') hook gets full request info AS the request flows.
  proxy.on("request", async (req) => {
    const bodyText = await req.body.getText().catch(() => undefined);
    captureEntry("mitm-proxy", {
      startedAt: req.timingEvents?.startTime ?? Date.now(),
      durationMs: 0,
      request: {
        method: req.method,
        url: req.url,
        headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : (v ?? "")])),
        body: bodyText?.slice(0, 8192) ?? undefined,
      },
      response: { status: 0, statusText: "", headers: {}, bodyLen: 0, bodySnippet: "" },
    }).catch(() => {});
  });

  await proxy.start(port);
  globalThis.__mobaTlsProxy = proxy;
  return {
    proxyPort: proxy.port,
    stop: async () => {
      await proxy.stop();
      globalThis.__mobaTlsProxy = undefined;
    },
  };
}

export async function stopTlsProxy(): Promise<void> {
  if (!globalThis.__mobaTlsProxy) return;
  await globalThis.__mobaTlsProxy.stop();
  globalThis.__mobaTlsProxy = undefined;
}

export function isTlsProxyRunning(): boolean {
  return !!globalThis.__mobaTlsProxy;
}

export async function getCaCertPem(): Promise<string | null> {
  try { return await fs.readFile(path.join(CA_DIR, "ca.cert"), "utf8"); }
  catch { return null; }
}

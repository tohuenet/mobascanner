/**
 * TLS configuration checker — built-in, uses Node's `tls` module.
 *
 * Connects to the host:port and inspects the negotiated certificate, protocol
 * version, and cipher suite. Emits findings for:
 *   - Self-signed / untrusted cert chains (we attempt strict verification)
 *   - Soon-to-expire certs (< 30 days)
 *   - Weak protocol negotiation (TLS 1.0/1.1)
 *   - Hostname mismatch
 */

import tls from "node:tls";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";

interface TlsInfo {
  authorized: boolean;
  authorizationError?: string;
  protocol?: string | null;
  cipher?: tls.CipherNameAndProtocol;
  cert: tls.PeerCertificate;
  servername: string;
}

function probeTls(host: string, port: number, servername: string, signal?: AbortSignal): Promise<TlsInfo | { error: string }> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host,
      port,
      servername,
      // Strict verification — we want to detect bad chains.
      rejectUnauthorized: false,
      ALPNProtocols: ["h2", "http/1.1"],
      timeout: 8000,
    });
    const onAbort = () => { try { socket.destroy(); } catch { /* noop */ } };
    if (signal) signal.addEventListener("abort", onAbort, { once: true });

    socket.on("secureConnect", () => {
      const cert = socket.getPeerCertificate(true);
      resolve({
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher() ?? undefined,
        cert,
        servername,
      });
      socket.end();
    });
    socket.on("timeout", () => { resolve({ error: "timeout" }); socket.destroy(); });
    socket.on("error", (e) => resolve({ error: e.message }));
  });
}

export const tlsScanner: Scanner = {
  id: "web.tls",
  name: "TLS Inspector",
  kind: "web",
  description: "Negotiates a TLS handshake against the target and reports weak protocol versions, expired certificates, hostname mismatches, and untrusted chains.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.tls",
      name: "TLS Inspector",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Built-in TLS handshake / certificate inspector.",
      upstream: "https://nodejs.org/api/tls.html",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) { await ctx.log("error", "invalid URL"); return; }
    if (url.protocol !== "https:") {
      await ctx.emit(draft({
        severity: "high",
        confidence: "high",
        title: "Target served over plain HTTP",
        description: "All connections to this origin are unencrypted. Sniffing on any intermediate hop reveals headers, cookies, and bodies.",
        ruleId: "tls/no-https",
        cwe: ["CWE-319"],
        owasp: ["A02:2021"],
        location: { url: url.toString() },
        remediation: "Serve the application over HTTPS only and add HSTS.",
        references: ["https://owasp.org/www-project-secure-headers/"],
      }));
      await ctx.progress(1, "non-HTTPS target");
      return;
    }

    const port = Number(url.port) || 443;
    await ctx.progress(0.3, `connecting to ${url.hostname}:${port}`);
    const result = await probeTls(url.hostname, port, url.hostname, ctx.signal);

    if ("error" in result) {
      await ctx.log("error", `TLS handshake error: ${result.error}`);
      await ctx.emit(draft({
        severity: "medium",
        confidence: "medium",
        title: "TLS handshake failed",
        description: `Could not complete a TLS handshake: ${result.error}`,
        ruleId: "tls/handshake-failed",
        location: { url: url.toString() },
      }));
      return;
    }

    await ctx.progress(0.7, "analyzing certificate");

    if (!result.authorized) {
      await ctx.emit(draft({
        severity: "high",
        confidence: "high",
        title: `Untrusted certificate chain: ${result.authorizationError ?? "unknown"}`,
        description: "The presented certificate did not validate against the system trust store.",
        ruleId: "tls/untrusted-chain",
        cwe: ["CWE-295"],
        owasp: ["A02:2021"],
        location: { url: url.toString() },
        evidence: { authorizationError: result.authorizationError },
      }));
    }

    if (result.protocol && /TLSv1(\.0|\.1)?$/i.test(result.protocol)) {
      await ctx.emit(draft({
        severity: "high",
        confidence: "high",
        title: `Weak TLS protocol negotiated: ${result.protocol}`,
        description: "TLS 1.0/1.1 are deprecated and considered insecure. Only TLS 1.2+ should be enabled.",
        ruleId: "tls/weak-protocol",
        cwe: ["CWE-326"],
        location: { url: url.toString() },
        evidence: { protocol: result.protocol, cipher: result.cipher },
        remediation: "Disable TLS 1.0/1.1 at the server / load balancer; enable TLS 1.2+ only.",
        references: ["https://datatracker.ietf.org/doc/rfc8996/"],
      }));
    }

    const validTo = result.cert?.valid_to ? new Date(result.cert.valid_to).getTime() : 0;
    if (validTo) {
      const daysLeft = Math.floor((validTo - Date.now()) / (1000 * 60 * 60 * 24));
      if (daysLeft < 0) {
        await ctx.emit(draft({
          severity: "critical",
          confidence: "high",
          title: `Certificate expired ${Math.abs(daysLeft)} day(s) ago`,
          description: "The leaf certificate has expired; modern browsers will refuse the connection.",
          ruleId: "tls/cert-expired",
          location: { url: url.toString() },
          evidence: { valid_to: result.cert.valid_to },
        }));
      } else if (daysLeft < 30) {
        await ctx.emit(draft({
          severity: "medium",
          confidence: "high",
          title: `Certificate expires in ${daysLeft} day(s)`,
          description: "The leaf certificate is approaching expiration.",
          ruleId: "tls/cert-expiring",
          location: { url: url.toString() },
          evidence: { valid_to: result.cert.valid_to },
        }));
      }
    }

    await ctx.progress(1, `done (${result.protocol ?? "?"})`);
  },
};

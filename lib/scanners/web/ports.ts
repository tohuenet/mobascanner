/**
 * TCP port scanner — built-in.
 *
 * Strategy: parallel TCP connect against a curated list of "high-signal"
 * ports (top services, mgmt panels, databases, mail, dev tools). Fast and
 * non-intrusive: a connect+RST is enough to confirm `LISTENING`. We never
 * send payloads, never run banner grabs that look like attack traffic.
 *
 * For each open port we additionally probe a few common service banners
 * (HTTP HEAD on http(s) ports, SMTP/FTP greeting on classic ports).
 */

import net from "node:net";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";

interface PortDef { port: number; service: string; risky?: "high" | "medium" | "low" | "info" }

// Curated list — much smaller than nmap's 65535 but covers >95% of real
// surfaces seen on the open internet. Risky tier flags ports that should
// almost never be exposed publicly.
const PORTS: PortDef[] = [
  { port: 21,    service: "ftp",          risky: "high" },
  { port: 22,    service: "ssh",          risky: "info" },
  { port: 23,    service: "telnet",       risky: "high" },
  { port: 25,    service: "smtp",         risky: "info" },
  { port: 53,    service: "dns",          risky: "info" },
  { port: 80,    service: "http" },
  { port: 110,   service: "pop3",         risky: "low" },
  { port: 111,   service: "rpcbind",      risky: "high" },
  { port: 135,   service: "msrpc",        risky: "high" },
  { port: 139,   service: "netbios-ssn",  risky: "high" },
  { port: 143,   service: "imap",         risky: "low" },
  { port: 161,   service: "snmp",         risky: "high" },
  { port: 389,   service: "ldap",         risky: "medium" },
  { port: 443,   service: "https" },
  { port: 445,   service: "smb",          risky: "high" },
  { port: 465,   service: "smtps" },
  { port: 587,   service: "smtp-submit" },
  { port: 636,   service: "ldaps" },
  { port: 873,   service: "rsync",        risky: "medium" },
  { port: 993,   service: "imaps" },
  { port: 995,   service: "pop3s" },
  { port: 1080,  service: "socks",        risky: "medium" },
  { port: 1433,  service: "mssql",        risky: "high" },
  { port: 1521,  service: "oracle",       risky: "high" },
  { port: 2049,  service: "nfs",          risky: "high" },
  { port: 2375,  service: "docker-api",   risky: "high" },
  { port: 2376,  service: "docker-tls",   risky: "high" },
  { port: 27017, service: "mongodb",      risky: "high" },
  { port: 3000,  service: "node-dev" },
  { port: 3001,  service: "node-dev" },
  { port: 3306,  service: "mysql",        risky: "high" },
  { port: 3389,  service: "rdp",          risky: "high" },
  { port: 4444,  service: "metasploit",   risky: "medium" },
  { port: 5000,  service: "upnp/flask" },
  { port: 5432,  service: "postgres",     risky: "high" },
  { port: 5601,  service: "kibana",       risky: "high" },
  { port: 5672,  service: "amqp",         risky: "medium" },
  { port: 5900,  service: "vnc",          risky: "high" },
  { port: 5984,  service: "couchdb",      risky: "high" },
  { port: 6379,  service: "redis",        risky: "high" },
  { port: 7474,  service: "neo4j",        risky: "high" },
  { port: 7687,  service: "neo4j-bolt",   risky: "high" },
  { port: 8000,  service: "http-alt" },
  { port: 8001,  service: "http-alt" },
  { port: 8008,  service: "http-alt" },
  { port: 8080,  service: "http-proxy" },
  { port: 8081,  service: "http-alt" },
  { port: 8086,  service: "influxdb",     risky: "high" },
  { port: 8088,  service: "hadoop",       risky: "high" },
  { port: 8090,  service: "confluence" },
  { port: 8443,  service: "https-alt" },
  { port: 8500,  service: "consul",       risky: "high" },
  { port: 8888,  service: "jupyter",      risky: "high" },
  { port: 9000,  service: "sonarqube/php-fpm" },
  { port: 9042,  service: "cassandra",    risky: "high" },
  { port: 9092,  service: "kafka",        risky: "high" },
  { port: 9200,  service: "elasticsearch",risky: "high" },
  { port: 9300,  service: "elasticsearch-tx", risky: "high" },
  { port: 11211, service: "memcached",    risky: "high" },
  { port: 15672, service: "rabbitmq-mgmt",risky: "high" },
  { port: 50000, service: "sap-jdbc",     risky: "high" },
];

function probePort(host: string, port: number, timeoutMs: number, signal?: AbortSignal): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open: boolean) => { if (done) return; done = true; socket.destroy(); resolve(open); };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    if (signal) signal.addEventListener("abort", () => finish(false), { once: true });
    socket.connect(port, host);
  });
}

async function grabBanner(host: string, port: number, signal?: AbortSignal): Promise<string | null> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let buf = "";
    const finish = (s: string | null) => { socket.destroy(); resolve(s); };
    socket.setTimeout(2000);
    socket.once("connect", () => {
      // For unknown protocols, just wait for greeting (SMTP/FTP/SSH banner-on-connect)
      // For HTTP-ish ports, send a HEAD probe.
      if ([80, 8000, 8001, 8008, 8080, 8081, 8088, 8090, 8888, 9000, 9200, 5601, 5984, 7474, 8500, 15672].includes(port)) {
        socket.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`);
      }
    });
    socket.on("data", (d) => {
      buf += d.toString("utf8");
      if (buf.length > 512) finish(buf.slice(0, 512));
    });
    socket.once("timeout", () => finish(buf || null));
    socket.once("error", () => finish(null));
    socket.once("close", () => finish(buf || null));
    if (signal) signal.addEventListener("abort", () => finish(null), { once: true });
    socket.connect(port, host);
  });
}

export const portsScanner: Scanner = {
  id: "web.ports",
  name: "Port Scanner",
  kind: "web",
  description: "Concurrent TCP connect scan over ~60 high-signal ports (services, DBs, mgmt panels). Flags databases / RPC / RDP exposed publicly.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.ports",
      name: "Port Scanner",
      kind: "web",
      backend: "builtin",
      status: "available",
      description: "Built-in TCP connect scanner.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) { await ctx.log("error", "invalid URL"); return; }
    const host = url.hostname;
    const timeout = Number(ctx.options.timeout) || 1500;
    const concurrency = Math.min(Number(ctx.options.concurrency) || 32, 128);

    let done = 0;
    const total = PORTS.length;
    const open: PortDef[] = [];

    let idx = 0;
    const workers = Array.from({ length: concurrency }, async () => {
      while (idx < PORTS.length && !ctx.signal.aborted) {
        const i = idx++;
        const p = PORTS[i];
        const isOpen = await probePort(host, p.port, timeout, ctx.signal);
        done += 1;
        if (done % 8 === 0) await ctx.progress(done / total, `${done}/${total} probed`);
        if (isOpen) open.push(p);
      }
    });
    await Promise.all(workers);

    await ctx.log("info", `${open.length} open ports of ${total} probed`);

    // Banner grab in parallel for open ports.
    await Promise.all(open.map(async (p) => {
      const banner = await grabBanner(host, p.port, ctx.signal);
      const sev = p.risky ?? "info";
      const isExpectedWeb = (p.port === 80 || p.port === 443) && (url.protocol === "http:" || url.protocol === "https:");
      if (isExpectedWeb && p.port === 443) return; // expected, no finding
      await ctx.emit(draft({
        severity: sev,
        confidence: "high",
        title: `Open port ${p.port}/tcp (${p.service})`,
        description: p.risky === "high"
          ? `Port ${p.port} exposes ${p.service}; this service is rarely safe to expose to the internet and is a frequent root cause of breaches.`
          : `Port ${p.port} (${p.service}) is reachable. Confirm exposure is intentional.`,
        ruleId: `ports/${p.service}`,
        cwe: ["CWE-200"],
        owasp: ["A05:2021"],
        location: { url: `${host}:${p.port}` },
        evidence: banner ? { banner: banner.replace(/[^\x20-\x7e\n\r]/g, ".").slice(0, 256) } : undefined,
        remediation: p.risky === "high"
          ? "Bind the service to localhost / private network, place behind a VPN or bastion, and add network ACLs."
          : "Confirm the service should be reachable from the public internet.",
      }));
    }));

    await ctx.progress(1, `${open.length} open`);
  },
};

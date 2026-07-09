/**
 * /api/tools/docker — one-click "full toolbox" via Docker.
 *
 * The Dockerfile bakes in EVERY external scanner CLI (nuclei, nmap, sqlmap,
 * semgrep, trivy, …), so a container built from it can run comprehensive scans
 * — unlike a bare host where only a handful of tools happen to be installed.
 * This endpoint lets the UI build & launch that image with one click.
 *
 *   GET  → docker/compose availability, whether the image is built, whether a
 *          container is already running (+ where), and whether WE are already
 *          inside the full image.
 *   POST → { action: "up" | "down", hostPort? } — runs `docker compose up
 *          --build -d` (or `down`) and streams the build/run output as NDJSON.
 *
 * SECURITY (mirrors /api/tools/install): localhost-only by default; the command
 * is a fixed `docker compose …` — the ONLY client input is a validated numeric
 * host port, passed via the MOBA_HOST_PORT env var (never as a shell string).
 * Runs through runCli (cross-spawn, no shell).
 */

import { NextResponse } from "next/server";
import { existsSync } from "node:fs";
import { runCli } from "@/lib/scanners/common";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DEFAULT_HOST_PORT = 3001; // avoid clashing with a dev server on :3000

// ── localhost guard (same policy as the install route) ──────────────────────
function isLoopback(addr: string): boolean {
  const a = addr.trim().replace(/^\[|\]$/g, "").toLowerCase();
  return a === "localhost" || a === "::1" || a === "::ffff:127.0.0.1" || a === "0.0.0.0" || /^127\./.test(a);
}
function hostnameOf(host: string): string {
  const h = host.trim().toLowerCase();
  if (h.startsWith("[")) { const end = h.indexOf("]"); return end === -1 ? h.slice(1) : h.slice(1, end); }
  return h.split(":").length === 2 ? h.split(":")[0] : h;
}
function isLocalRequest(req: Request): boolean {
  if (!isLoopback(hostnameOf(req.headers.get("host") ?? ""))) return false;
  const xff = req.headers.get("x-forwarded-for");
  if (xff && !xff.split(",").map((s) => s.trim()).filter(Boolean).every(isLoopback)) return false;
  return true;
}
function actionAllowed(req: Request): boolean {
  return process.env.MOBA_ALLOW_REMOTE_INSTALL === "1" || isLocalRequest(req);
}

// ── docker probes ───────────────────────────────────────────────────────────
async function dockerVersion(): Promise<string | null> {
  const r = await runCli("docker", ["--version"], { timeoutMs: 8000 });
  if (r.spawnError || r.code !== 0) return null;
  return r.stdout.trim() || "docker";
}
async function composeAvailable(): Promise<boolean> {
  const r = await runCli("docker", ["compose", "version"], { timeoutMs: 8000 });
  return !r.spawnError && r.code === 0;
}
/** The CLI can be installed while the engine (Docker Desktop) is stopped —
 *  `docker ps` needs the daemon, so it's a good liveness probe. */
async function daemonRunning(): Promise<boolean> {
  const r = await runCli("docker", ["ps", "-q"], { timeoutMs: 8000 });
  return !r.spawnError && r.code === 0;
}
async function imageBuilt(): Promise<boolean> {
  const r = await runCli("docker", ["image", "inspect", "moba-scanner:latest"], { timeoutMs: 8000 });
  return !r.spawnError && r.code === 0;
}
async function runningContainer(): Promise<{ running: boolean; ports: string | null }> {
  const r = await runCli("docker", ["ps", "--filter", "ancestor=moba-scanner:latest", "--format", "{{.Names}}\t{{.Ports}}"], { timeoutMs: 8000 });
  if (r.spawnError || r.code !== 0) return { running: false, ports: null };
  const line = r.stdout.trim().split("\n").filter(Boolean)[0];
  if (!line) return { running: false, ports: null };
  return { running: true, ports: line.split("\t")[1]?.trim() || null };
}

export async function GET(req: Request) {
  const inDocker = existsSync("/.dockerenv");
  const version = await dockerVersion();
  const available = !!version;
  const [compose, daemon] = available
    ? await Promise.all([composeAvailable(), daemonRunning()])
    : [false, false];
  // image/container probes need the daemon.
  const [built, running] = available && daemon
    ? await Promise.all([imageBuilt(), runningContainer()])
    : [false, { running: false, ports: null } as const];
  return NextResponse.json({
    local: actionAllowed(req),
    inDocker,
    docker: { available, version, compose, daemon },
    image: { built },
    container: running,
    defaultHostPort: DEFAULT_HOST_PORT,
    command: `docker compose up --build -d`,
  });
}

export async function POST(req: Request) {
  if (!actionAllowed(req)) {
    return NextResponse.json(
      { error: "Docker actions can only be triggered from localhost (or set MOBA_ALLOW_REMOTE_INSTALL=1)." },
      { status: 403 },
    );
  }

  let body: { action?: unknown; hostPort?: unknown };
  try { body = await req.json(); } catch { body = {}; }

  const action = body.action === "down" ? "down" : "up";
  let hostPort = DEFAULT_HOST_PORT;
  if (typeof body.hostPort === "number" && Number.isInteger(body.hostPort) && body.hostPort >= 1024 && body.hostPort <= 65535) {
    hostPort = body.hostPort;
  }

  const args = action === "down" ? ["compose", "down"] : ["compose", "up", "--build", "-d"];

  const enc = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (obj: unknown) => {
        try { controller.enqueue(enc.encode(JSON.stringify(obj) + "\n")); } catch { /* closed */ }
      };

      send({ type: "start", action, hostPort, command: `docker ${args.join(" ")}` });

      const result = await runCli("docker", args, {
        cwd: process.cwd(),
        // Merge — runCli replaces process.env wholesale otherwise, which would
        // drop PATH and break docker.
        env: { ...process.env, MOBA_HOST_PORT: String(hostPort) },
        signal: req.signal,
        timeoutMs: 40 * 60 * 1000, // first build downloads GBs of tools
        onStdout: (line) => send({ type: "log", stream: "stdout", line }),
        onStderr: (line) => send({ type: "log", stream: "stderr", line }),
      });

      if (result.spawnError) {
        send({ type: "error", message: `Could not start docker: ${result.spawnError}. Install Docker Desktop and make sure it's running.` });
        send({ type: "done", ok: false });
        try { controller.close(); } catch {}
        return;
      }

      send({ type: "exit", code: result.code, signal: result.signal });
      if (action === "up" && result.code === 0) {
        send({ type: "ready", url: `http://localhost:${hostPort}`, hostPort });
      }
      send({ type: "done", ok: result.code === 0, code: result.code });
      try { controller.close(); } catch {}
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-cache, no-transform, no-store",
      "X-Accel-Buffering": "no",
    },
  });
}

/**
 * /api/tools/install — one-click installer for the external scanner CLIs.
 *
 *   GET  → install plans for every recipe-backed tool + which package managers
 *          are present on this machine + whether the caller is local.
 *   POST → run a single tool's install command and stream its output as NDJSON,
 *          then re-detect the tool so the UI can flip its status.
 *
 * SECURITY: POST is localhost-only and never executes anything derived from the
 * request body. The client sends a scanner `id` (+ optional method index); the
 * actual command comes from the server-side recipe table and runs via `runCli`
 * (cross-spawn, no shell). Inside the Docker image these installs mutate only
 * the running container — losses on container recreate are expected.
 */

import { NextResponse } from "next/server";
import { runCli } from "@/lib/scanners/common";
import { getScanner } from "@/lib/engine/registry";
import {
  detectManagers,
  getAllInstallPlans,
  getInstallPlan,
  hasRecipe,
  resolveMethod,
} from "@/lib/install/recipes";
import "@/lib/scanners";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** True for loopback hosts/addresses (IPv4 127.0.0.0/8, IPv6 ::1, localhost). */
function isLoopback(addr: string): boolean {
  const a = addr.trim().replace(/^\[|\]$/g, "").toLowerCase();
  return (
    a === "localhost" ||
    a === "::1" ||
    a === "::ffff:127.0.0.1" ||
    a === "0.0.0.0" ||
    /^127\./.test(a)
  );
}

/** Extract the hostname from a Host header, handling :port and [IPv6]:port. */
function hostnameOf(host: string): string {
  const h = host.trim().toLowerCase();
  if (h.startsWith("[")) {
    const end = h.indexOf("]");
    return end === -1 ? h.slice(1) : h.slice(1, end);
  }
  // Only strip a trailing :port for host:port (not bare IPv6 like ::1).
  return h.split(":").length === 2 ? h.split(":")[0] : h;
}

/**
 * A request counts as local when it reached a loopback host AND every hop in
 * the forwarded chain (if any) is itself loopback. A local proxy that appends
 * `x-forwarded-for: ::1` is fine; a real remote client (whose XFF carries a
 * public/LAN address) is not.
 */
function isLocalRequest(req: Request): boolean {
  if (!isLoopback(hostnameOf(req.headers.get("host") ?? ""))) return false;
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const hops = xff.split(",").map((s) => s.trim()).filter(Boolean);
    if (!hops.every(isLoopback)) return false;
  }
  return true;
}

/**
 * Installs are allowed from a local request, or when the operator has
 * explicitly opted in via MOBA_ALLOW_REMOTE_INSTALL=1 (for intentional
 * single-user remote/self-hosted setups). Off by default — safe by default.
 */
function installAllowed(req: Request): boolean {
  return process.env.MOBA_ALLOW_REMOTE_INSTALL === "1" || isLocalRequest(req);
}

export async function GET(req: Request) {
  const [plans, managers] = await Promise.all([getAllInstallPlans(), detectManagers()]);
  return NextResponse.json({ local: installAllowed(req), managers, plans });
}

export async function POST(req: Request) {
  if (!installAllowed(req)) {
    return NextResponse.json(
      { error: "Installs can only be triggered from localhost (or set MOBA_ALLOW_REMOTE_INSTALL=1)." },
      { status: 403 },
    );
  }

  let body: { id?: unknown; methodIndex?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const id = typeof body.id === "string" ? body.id : "";
  if (!id || !hasRecipe(id)) {
    return NextResponse.json({ error: "Unknown or non-installable tool id." }, { status: 404 });
  }
  const scanner = getScanner(id);
  if (!scanner) {
    return NextResponse.json({ error: "Tool id is not a registered scanner." }, { status: 404 });
  }

  // Pick the method: an explicit (validated) index, else the first available one.
  let methodIndex: number;
  if (body.methodIndex === undefined || body.methodIndex === null) {
    const plan = await getInstallPlan(id);
    if (!plan || plan.availableIndex === null) {
      return NextResponse.json(
        { error: "No supported package manager was detected for this tool." },
        { status: 400 },
      );
    }
    methodIndex = plan.availableIndex;
  } else if (typeof body.methodIndex === "number") {
    methodIndex = body.methodIndex;
  } else {
    return NextResponse.json({ error: "methodIndex must be a number." }, { status: 400 });
  }

  const method = resolveMethod(id, methodIndex);
  if (!method) {
    return NextResponse.json({ error: "Invalid methodIndex for this tool." }, { status: 400 });
  }

  const enc = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (obj: unknown) => {
        try {
          controller.enqueue(enc.encode(JSON.stringify(obj) + "\n"));
        } catch {
          /* stream already closed */
        }
      };

      send({
        type: "start",
        id,
        label: method.label,
        note: method.note ?? null,
        command: `${method.cmd} ${method.args.join(" ")}`,
      });

      const result = await runCli(method.cmd, method.args, {
        signal: req.signal,
        timeoutMs: 10 * 60 * 1000, // installs (esp. `go install`) can be slow
        onStdout: (line) => send({ type: "log", stream: "stdout", line }),
        onStderr: (line) => send({ type: "log", stream: "stderr", line }),
      });

      if (result.spawnError) {
        send({ type: "error", message: `Could not start \`${method.cmd}\`: ${result.spawnError}` });
        send({ type: "done", ok: false });
        try { controller.close(); } catch {}
        return;
      }

      send({ type: "exit", code: result.code, signal: result.signal });

      // Re-detect so the UI can update the status chip without a full refresh.
      try {
        const tool = await scanner.tool();
        send({ type: "status", status: tool.status, version: tool.detectedVersion ?? null });
      } catch {
        /* tool() failed — leave the existing status in place */
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

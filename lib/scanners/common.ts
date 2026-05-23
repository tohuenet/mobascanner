/**
 * Shared helpers for adapters.
 */

import spawn from "cross-spawn";
import { promises as fs } from "node:fs";
import path from "node:path";

export interface RunCliResult {
  stdout: string;
  stderr: string;
  code: number;
  signal: NodeJS.Signals | null;
  /** True if the binary couldn't even be spawned (e.g. ENOENT). */
  spawnError?: string;
}

/**
 * Run a CLI tool and capture its output. We intentionally don't throw on
 * non-zero exit codes — many security tools use exit codes to signal "vulns
 * found", which is the *expected* path. Caller decides how to interpret.
 */
export function runCli(
  cmd: string,
  args: string[],
  opts: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    timeoutMs?: number;
    stdin?: string;
    signal?: AbortSignal;
    /** Stream stdout line-by-line (for progress). */
    onStdout?: (line: string) => void;
    onStderr?: (line: string) => void;
    /** Cap stdout buffer size to avoid OOM on chatty tools. */
    maxBufferBytes?: number;
  } = {},
): Promise<RunCliResult> {
  return new Promise((resolve) => {
    let proc: ReturnType<typeof spawn>;
    try {
      // cross-spawn: handles Windows `.cmd`/`.bat` resolution WITHOUT setting
      // shell:true, so user-supplied args can never be re-parsed by a shell.
      // This is the recommended pattern for security tools that exec child CLIs.
      proc = spawn(cmd, args, {
        cwd: opts.cwd,
        env: opts.env ?? process.env,
        windowsHide: true,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      resolve({ stdout: "", stderr: msg, code: -1, signal: null, spawnError: msg });
      return;
    }

    const max = opts.maxBufferBytes ?? 16 * 1024 * 1024;
    let stdout = "";
    let stderr = "";
    let stdoutBuf = "";
    let stderrBuf = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const flushLines = (buf: string, sink: (line: string) => void): string => {
      let i = buf.indexOf("\n");
      while (i !== -1) {
        sink(buf.slice(0, i));
        buf = buf.slice(i + 1);
        i = buf.indexOf("\n");
      }
      return buf;
    };

    proc.stdout?.on("data", (chunk: Buffer) => {
      const s = chunk.toString();
      stdoutBytes += chunk.length;
      if (stdoutBytes <= max) stdout += s;
      if (opts.onStdout) {
        stdoutBuf += s;
        stdoutBuf = flushLines(stdoutBuf, opts.onStdout!);
      }
    });
    proc.stderr?.on("data", (chunk: Buffer) => {
      const s = chunk.toString();
      stderrBytes += chunk.length;
      if (stderrBytes <= max) stderr += s;
      if (opts.onStderr) {
        stderrBuf += s;
        stderrBuf = flushLines(stderrBuf, opts.onStderr!);
      }
    });

    proc.on("error", (err) => {
      resolve({ stdout, stderr: stderr || err.message, code: -1, signal: null, spawnError: err.message });
    });

    proc.on("close", (code, signal) => {
      if (opts.onStdout && stdoutBuf) opts.onStdout(stdoutBuf);
      if (opts.onStderr && stderrBuf) opts.onStderr(stderrBuf);
      resolve({ stdout, stderr, code: code ?? -1, signal });
    });

    if (opts.stdin) {
      proc.stdin?.end(opts.stdin);
    }

    if (opts.timeoutMs) {
      setTimeout(() => { try { proc.kill("SIGKILL"); } catch { /* noop */ } }, opts.timeoutMs);
    }
    if (opts.signal) {
      opts.signal.addEventListener("abort", () => { try { proc.kill("SIGKILL"); } catch { /* noop */ } }, { once: true });
    }
  });
}

/** Quick check whether a CLI is on PATH and executable. Returns version string or null. */
export async function detectCli(cmd: string, versionArg = "--version"): Promise<string | null> {
  const r = await runCli(cmd, [versionArg], { timeoutMs: 8000 });
  if (r.spawnError) return null;
  if (r.code !== 0 && !r.stdout && !r.stderr) return null;
  const txt = (r.stdout || r.stderr).split(/\r?\n/)[0]?.trim() ?? "";
  return txt || (r.code === 0 ? "available" : null);
}

/** Recursively list files under a directory, with simple ignore list. */
export async function* walkFiles(
  root: string,
  opts: { ignore?: string[]; maxFiles?: number } = {},
): AsyncGenerator<string> {
  const ignore = new Set(opts.ignore ?? [
    ".git", "node_modules", ".next", "dist", "build", "out", "venv", ".venv",
    "__pycache__", "target", "vendor", ".idea", ".vscode",
  ]);
  let count = 0;
  async function* walk(dir: string): AsyncGenerator<string> {
    let entries: import("node:fs").Dirent[];
    try { entries = await fs.readdir(dir, { withFileTypes: true }); }
    catch { return; }
    for (const e of entries) {
      if (ignore.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) yield* walk(full);
      else if (e.isFile()) {
        count += 1;
        if (opts.maxFiles && count > opts.maxFiles) return;
        yield full;
      }
    }
  }
  yield* walk(root);
}

/** Truncate snippets for evidence storage. */
export function truncate(s: string, max = 400): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + "…";
}

/** Safe URL parse; returns null on invalid input. */
export function safeUrl(input: string): URL | null {
  try { return new URL(input); } catch { return null; }
}

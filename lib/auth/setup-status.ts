/**
 * Browser-capture setup status + one-click Chromium installer.
 *
 * Two checks the UI needs to render a self-serve "setup" panel:
 *   1. Is the vault master secret available? (After the auto-bootstrap in
 *      lib/vault/encrypted.ts this is effectively always true on first call;
 *      we still expose it so the UI shows a green tick.)
 *   2. Is the Chromium binary installed?
 *
 * If Chromium isn't installed, the user triggers the install from the UI and
 * we spawn `node playwright-core/cli.js install chromium` in the background.
 * Progress is captured into a small in-memory ring buffer the status endpoint
 * returns so the UI can stream the log without us standing up an SSE channel.
 */

import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { existsSync } from "node:fs";
import { ensureVaultKey, vaultKeyConfigured } from "../vault/encrypted";

interface InstallState {
  running: boolean;
  startedAt?: number;
  finishedAt?: number;
  exitCode?: number | null;
  /** Ring buffer of the last ~4 KB of combined stdout/stderr. */
  log: string;
  error?: string;
}

declare global {
  // eslint-disable-next-line no-var
  var __mobaChromiumInstall: { state: InstallState; proc?: ChildProcess } | undefined;
}
const g = (globalThis.__mobaChromiumInstall ??= {
  state: { running: false, log: "" },
});

const LOG_CAP = 4096;
function appendLog(chunk: string) {
  const next = (g.state.log + chunk);
  g.state.log = next.length > LOG_CAP ? next.slice(next.length - LOG_CAP) : next;
}

/** Resolve the Chromium executable path without booting a browser. Returns
 *  null if playwright-core can't find it (binary not installed yet). */
export async function chromiumInstalled(): Promise<boolean> {
  try {
    const pw = await import("playwright-core");
    const p = pw.chromium.executablePath();
    return Boolean(p) && existsSync(p);
  } catch {
    return false;
  }
}

export interface SetupStatus {
  vault: boolean;
  chromium: boolean;
  installing: boolean;
  installLog: string;
  /** When the last install finished, the exit code. Null while running, or
   *  unset if no install has been attempted in this process. */
  installExitCode?: number | null;
  installError?: string;
  ready: boolean;
}

export async function readSetupStatus(): Promise<SetupStatus> {
  // Force the vault key to materialize so the checklist never blinks red
  // on a fresh install — the user shouldn't have to do anything for the
  // local encryption-at-rest layer to "just work".
  try { ensureVaultKey(); } catch { /* surfaced via vault = false below */ }
  const vault = vaultKeyConfigured();
  const chromium = await chromiumInstalled();
  return {
    vault,
    chromium,
    installing: g.state.running,
    installLog: g.state.log,
    installExitCode: g.state.exitCode,
    installError: g.state.error,
    ready: vault && chromium,
  };
}

/** Kick off `playwright-core install chromium` if it isn't already running.
 *  Idempotent: returns the current state either way. */
export async function startChromiumInstall(): Promise<SetupStatus> {
  if (g.state.running) return readSetupStatus();
  if (await chromiumInstalled()) return readSetupStatus();

  // Reset state for this run.
  g.state = { running: true, startedAt: Date.now(), log: "" };

  // Locate the playwright-core CLI shipped in node_modules. Using `node` with
  // the explicit script path avoids depending on the shell finding `npx`.
  const cli = path.join(process.cwd(), "node_modules", "playwright-core", "cli.js");
  appendLog(`$ node ${path.relative(process.cwd(), cli)} install chromium\n`);
  try {
    const proc = spawn(process.execPath, [cli, "install", "chromium"], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    g.proc = proc;
    proc.stdout?.on("data", (b: Buffer) => appendLog(b.toString()));
    proc.stderr?.on("data", (b: Buffer) => appendLog(b.toString()));
    proc.on("error", (e) => {
      g.state.error = e.message;
      g.state.running = false;
      g.state.finishedAt = Date.now();
    });
    proc.on("close", (code) => {
      g.state.running = false;
      g.state.exitCode = code;
      g.state.finishedAt = Date.now();
      appendLog(`\n[install exited with code ${code}]\n`);
    });
  } catch (e) {
    g.state.error = e instanceof Error ? e.message : String(e);
    g.state.running = false;
    g.state.finishedAt = Date.now();
  }
  return readSetupStatus();
}

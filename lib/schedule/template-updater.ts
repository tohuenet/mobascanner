/**
 * Daily template auto-updater — keeps nuclei templates and our YAML rules
 * fresh.
 *
 * Tasks:
 *   1. `nuclei -update-templates -silent` (if nuclei installed) — pulls fresh
 *       community templates into ~/.config/nuclei/templates/.
 *   2. Reload our custom-rules cache (so YAML edits take effect within 30s
 *      anyway, but this triggers an immediate refresh after a git pull).
 *
 * Runs once at startup, then every 24h. Idempotent — multiple imports won't
 * stack timers.
 */

import { runCli } from "../scanners/common";

declare global {
  // eslint-disable-next-line no-var
  var __mobaTemplateUpdater: NodeJS.Timeout | undefined;
}

let started = false;

async function tick() {
  // Update nuclei templates if available.
  try {
    const r = await runCli("nuclei", ["-update-templates", "-silent", "-duc"], { timeoutMs: 5 * 60 * 1000 });
    if (r.spawnError) return; // nuclei not installed — silently skip
    console.info("[template-updater] nuclei templates checked for updates");
  } catch { /* tolerate */ }
}

export function startTemplateUpdater() {
  if (started || globalThis.__mobaTemplateUpdater) return;
  started = true;
  // First run after 2 minutes (give the app time to boot), then daily.
  setTimeout(tick, 2 * 60 * 1000).unref();
  globalThis.__mobaTemplateUpdater = setInterval(tick, 24 * 60 * 60 * 1000);
  globalThis.__mobaTemplateUpdater.unref();
}

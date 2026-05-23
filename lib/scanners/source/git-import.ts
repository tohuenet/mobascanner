/**
 * Resolves a source-scan target to a local directory we can scan.
 *
 *   - "git" target  → shallow `git clone` into data/repos/<scanId>
 *   - "local" target → use as-is
 *   - "archive" target → not yet implemented
 *
 * Always returns an absolute path or throws. Caller is responsible for cleanup
 * if it cloned (we keep the working copy alive for the lifetime of the scan
 * so multiple scanners can read from it concurrently).
 */

import path from "node:path";
import { promises as fs } from "node:fs";
import simpleGit from "simple-git";
import type { ScanTarget } from "../../types";

const REPOS_ROOT = path.join(process.cwd(), "data", "repos");

export async function resolveSourceTarget(
  scanId: string,
  target: ScanTarget,
  log: (level: "info" | "warn" | "error", msg: string) => Promise<void>,
): Promise<string> {
  if (target.type === "local") {
    const abs = path.resolve(target.value);
    const stat = await fs.stat(abs).catch(() => null);
    if (!stat || !stat.isDirectory()) throw new Error(`local path not a directory: ${abs}`);
    return abs;
  }

  if (target.type === "git") {
    await fs.mkdir(REPOS_ROOT, { recursive: true });
    const dest = path.join(REPOS_ROOT, scanId);
    await fs.rm(dest, { recursive: true, force: true });
    await log("info", `cloning ${target.value} → ${dest}`);
    const git = simpleGit({ baseDir: REPOS_ROOT });
    const args = ["--depth", "1"];
    if (target.ref) args.push("--branch", target.ref);
    await git.clone(target.value, dest, args);
    return dest;
  }

  throw new Error(`source target type "${target.type}" not supported yet`);
}

export async function cleanupSourceTarget(scanId: string): Promise<void> {
  const dir = path.join(REPOS_ROOT, scanId);
  await fs.rm(dir, { recursive: true, force: true });
}

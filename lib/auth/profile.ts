/**
 * Login profile scaffolding — captures storageState (cookies + localStorage
 * + sessionStorage + IndexedDB) for replay before each scan.
 *
 * Today: takes a Playwright-shaped storageState JSON (the user can produce
 * with `npx playwright codegen` + manual login) and stores it encrypted in
 * the vault.
 *
 * Tomorrow (when we ship the in-app recorder): the recorder UI uses
 * `chromium.launch()` → user logs in → we save the same shape automatically.
 *
 * Replay: every web scanner can call `loadAuthHeaders(profileId)` and pass
 * the cookies into BrowsingSession's extraHeaders. The cookies cover most
 * apps; for SPAs that key off localStorage, scanners need to use a real
 * Playwright browser context — out of scope for this scaffold.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { vaultDelete, vaultGet, vaultList, vaultPut } from "../vault/encrypted";

/**
 * On-disk persistent Chrome profile directory for a login profile. Keeping a
 * real (persistent) profile — not just a storageState snapshot — means the
 * login survives across scans AND localStorage / IndexedDB / service-worker
 * auth works, not only cookies. Lives under the gitignored `data/` tree.
 */
export function profileDir(id: string): string {
  const safe = id.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64) || "default";
  return path.join(process.cwd(), "data", "browser-profiles", safe);
}

/** True if a persistent Chrome profile has been created for this id. */
export async function profileDirExists(id: string): Promise<boolean> {
  try {
    const st = await fs.stat(profileDir(id));
    return st.isDirectory();
  } catch {
    return false;
  }
}

export interface StorageState {
  cookies?: Array<{ name: string; value: string; domain: string; path: string; expires?: number; secure?: boolean; httpOnly?: boolean; sameSite?: string }>;
  origins?: Array<{ origin: string; localStorage?: Array<{ name: string; value: string }> }>;
}

const VAULT_PREFIX = "loginprofile:";

export async function saveProfile(id: string, state: StorageState): Promise<void> {
  await vaultPut(VAULT_PREFIX + id, JSON.stringify(state));
}

export async function loadProfile(id: string): Promise<StorageState | null> {
  const raw = await vaultGet(VAULT_PREFIX + id);
  if (!raw) return null;
  try { return JSON.parse(raw) as StorageState; } catch { return null; }
}

export interface ProfileSummary {
  id: string;
  cookieCount: number;
  originCount: number;
  /** Distinct cookie domains in the profile (helps the user know what host it
   *  was captured for — e.g. ".widata.vn"). */
  domains: string[];
}

/** List every saved login profile (id + cheap metadata, no secrets). */
export async function listProfiles(): Promise<ProfileSummary[]> {
  const keys = await vaultList();
  const out: ProfileSummary[] = [];
  for (const k of keys) {
    if (!k.startsWith(VAULT_PREFIX)) continue;
    const id = k.slice(VAULT_PREFIX.length);
    const state = await loadProfile(id);
    if (!state) continue;
    const domains = Array.from(
      new Set((state.cookies ?? []).map((c) => c.domain).filter(Boolean)),
    ).sort();
    out.push({
      id,
      cookieCount: state.cookies?.length ?? 0,
      originCount: state.origins?.length ?? 0,
      domains,
    });
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

/** Remove a saved profile — both the vault snapshot and its persistent Chrome
 *  profile directory. Idempotent. */
export async function deleteProfile(id: string): Promise<void> {
  await vaultDelete(VAULT_PREFIX + id);
  await fs.rm(profileDir(id), { recursive: true, force: true }).catch(() => undefined);
}

/** Convert a stored profile into Cookie + extra headers BrowsingSession can use. */
export async function profileToHeaders(id: string, currentOrigin: string): Promise<Record<string, string>> {
  const state = await loadProfile(id);
  if (!state) return {};
  const targetHost = (() => { try { return new URL(currentOrigin).host; } catch { return ""; } })();

  const cookies = (state.cookies ?? []).filter((c) => {
    // Match by domain suffix (basic — for production, full RFC 6265 matching).
    if (!c.domain) return false;
    const d = c.domain.replace(/^\./, "");
    return targetHost === d || targetHost.endsWith("." + d);
  });
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
  const headers: Record<string, string> = {};
  if (cookieHeader) headers["cookie"] = cookieHeader;
  return headers;
}

/**
 * Login recorder — opens a REAL Chrome window (persistent profile, automation
 * tells stripped), lets the user log in by hand, and captures the resulting
 * session for replay.
 *
 * Why real Chrome + persistent + stealth: bot-detection and Google's sign-in
 * flow refuse browsers that look automated (`navigator.webdriver`, the
 * `--enable-automation` flag, bundled-Chromium fingerprint, `--remote-debugging-port`).
 * By launching the user's installed Chrome with those tells removed and letting
 * the HUMAN do the login (the tool performs zero automation during login), the
 * "This browser or app may not be secure" block and CAPTCHA walls stand down.
 *
 * The persistent profile dir (`data/browser-profiles/<id>`) survives, so later
 * scans reuse the SAME authenticated session — cookies AND localStorage /
 * IndexedDB — not just a one-shot cookie snapshot.
 *
 * Usage:
 *   1. POST /api/auth-record/start { url, profileId } — opens the Chrome window.
 *   2. User logs in (Google, SSO, whatever), solving any CAPTCHA once, as a human.
 *   3. POST /api/auth-record/save { profileId } — snapshots storageState into the
 *      vault (for the fetch-based scanners) and closes the window; the profile
 *      dir stays for browser-based scanners.
 */

import type { BrowserContext, Page } from "playwright-core";
import { saveProfile, profileDir, type StorageState } from "./profile";
import { launchStealthPersistent } from "../web/browser";

declare global {
  var __mobaRecorderSessions: Map<string, { context: BrowserContext; page: Page; usedRealChrome: boolean }> | undefined;
}
const sessions = (globalThis.__mobaRecorderSessions ??= new Map());

export async function startRecording(profileId: string, url: string): Promise<{ profileId: string; status: string; realChrome: boolean }> {
  if (sessions.has(profileId)) throw new Error(`recording already in progress for profile ${profileId}`);
  const { context, usedRealChrome } = await launchStealthPersistent(profileDir(profileId), { headless: false });
  const page = context.pages()[0] ?? (await context.newPage());
  // Navigate but never fail the start on a slow/redirecting login page.
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 }).catch(() => {});
  sessions.set(profileId, { context, page, usedRealChrome });
  return {
    profileId,
    realChrome: usedRealChrome,
    status: usedRealChrome
      ? "A real Chrome window opened. Log in (Google/SSO ok), then click Save."
      : "Chrome not found — opened bundled Chromium (Google login may still be blocked). Log in, then Save.",
  };
}

export async function saveRecording(profileId: string): Promise<{ profileId: string; cookieCount: number; originCount: number }> {
  const session = sessions.get(profileId);
  if (!session) throw new Error("no recording in progress");
  const state = (await session.context.storageState()) as StorageState;
  await saveProfile(profileId, state);
  await session.context.close().catch(() => undefined);
  sessions.delete(profileId);
  return {
    profileId,
    cookieCount: state.cookies?.length ?? 0,
    originCount: state.origins?.length ?? 0,
  };
}

export async function cancelRecording(profileId: string): Promise<void> {
  const s = sessions.get(profileId);
  if (!s) return;
  await s.context.close().catch(() => undefined);
  sessions.delete(profileId);
}

export function listSessions(): string[] {
  return [...sessions.keys()];
}

/**
 * Playwright login recorder — opens a real Chromium tab, lets the user log
 * in by hand, and captures the resulting `storageState` (cookies +
 * localStorage + sessionStorage + IndexedDB) for replay.
 *
 * Usage:
 *   1. POST /api/auth-record/start { url, profileId } — spawns a browser
 *      window, returns a CDP/WS endpoint the user can join via DevTools or
 *      a noVNC viewer, OR (simplest) just a prompt to log in in the popped-
 *      open browser.
 *   2. User logs in.
 *   3. POST /api/auth-record/save { profileId } — captures storageState,
 *      encrypts via the vault, closes the browser.
 *
 * Requires `playwright-core` + chromium binary (`npx playwright install
 * chromium`). The package is installed but binary install is up to the user.
 *
 * Each session held in a global Map by profileId so the start/save flow
 * spans two HTTP requests in the same Node process.
 */

import type { Browser, BrowserContext, Page } from "playwright-core";
import { saveProfile, type StorageState } from "./profile";

declare global {
  // eslint-disable-next-line no-var
  var __mobaRecorderSessions: Map<string, { browser: Browser; context: BrowserContext; page: Page }> | undefined;
}
const sessions = (globalThis.__mobaRecorderSessions ??= new Map());

let chromiumPromise: Promise<typeof import("playwright-core").chromium> | null = null;
async function getChromium() {
  if (!chromiumPromise) chromiumPromise = import("playwright-core").then((m) => m.chromium);
  return chromiumPromise;
}

export async function startRecording(profileId: string, url: string): Promise<{ profileId: string; status: string }> {
  if (sessions.has(profileId)) throw new Error(`recording already in progress for profile ${profileId}`);
  const chromium = await getChromium();
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 });
  sessions.set(profileId, { browser, context, page });
  return { profileId, status: "recording — log in via the open Chromium window, then POST /api/auth-record/save" };
}

export async function saveRecording(profileId: string): Promise<{ profileId: string; cookieCount: number; originCount: number }> {
  const session = sessions.get(profileId);
  if (!session) throw new Error("no recording in progress");
  const state = await session.context.storageState() as StorageState;
  await saveProfile(profileId, state);
  await session.browser.close();
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
  await s.browser.close();
  sessions.delete(profileId);
}

export function listSessions(): string[] {
  return [...sessions.keys()];
}

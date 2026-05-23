/**
 * Scheduled scans — periodic re-runs against saved targets.
 *
 * Storage: data/schedules.json (array of Schedule entries).
 * Tick: a global setInterval started by the API route on first read.
 *
 * Why not full cron syntax: 95% of users need either "every N minutes" or
 * "daily at HH:MM". We expose `intervalMinutes` and `dailyAt` (HH:MM in
 * the server's timezone). Real cron can be added if anyone asks.
 *
 * On each tick, schedules that are due → POST to /api/scans with the saved
 * config → fire-and-forget. Webhook notifications (if configured) fire on
 * scan completion.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";

const FILE = path.join(process.cwd(), "data", "schedules.json");

export const ScheduleSchema = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean().default(true),
  /** Same shape as POST /api/scans body. */
  scanRequest: z.object({
    kind: z.enum(["web", "source"]),
    target: z.object({
      value: z.string(),
      type: z.enum(["url", "git", "local", "archive"]),
      ref: z.string().optional(),
    }),
    selection: z.object({
      enabled: z.array(z.string()),
      options: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
    }),
  }),
  /** Run every N minutes. Mutually exclusive with dailyAt. */
  intervalMinutes: z.number().min(5).optional(),
  /** Run daily at HH:MM (server local time). */
  dailyAt: z.string().regex(/^\d{2}:\d{2}$/).optional(),
  /** Last run timestamp (ms). */
  lastRunAt: z.number().optional(),
  /** Last scan id produced. */
  lastScanId: z.string().optional(),
  /** Notify after each run. */
  notify: z.object({
    webhookUrl: z.string().url().optional(),
    onlyOnNew: z.boolean().default(false),
    onlyCriticalHigh: z.boolean().default(false),
  }).optional(),
});
export type Schedule = z.infer<typeof ScheduleSchema>;

async function load(): Promise<Schedule[]> {
  try { return JSON.parse(await fs.readFile(FILE, "utf8")); }
  catch { return []; }
}
async function save(items: Schedule[]) {
  await fs.mkdir(path.dirname(FILE), { recursive: true });
  await fs.writeFile(FILE, JSON.stringify(items, null, 2), "utf8");
}

export async function listSchedules(): Promise<Schedule[]> {
  return load();
}
export async function createSchedule(input: Omit<Schedule, "id">): Promise<Schedule> {
  const items = await load();
  const s: Schedule = { ...input, id: randomUUID() };
  items.push(s);
  await save(items);
  return s;
}
export async function deleteSchedule(id: string): Promise<void> {
  const items = (await load()).filter((s) => s.id !== id);
  await save(items);
}
export async function updateSchedule(id: string, patch: Partial<Schedule>): Promise<Schedule | null> {
  const items = await load();
  const i = items.findIndex((s) => s.id === id);
  if (i < 0) return null;
  items[i] = { ...items[i], ...patch };
  await save(items);
  return items[i];
}

/** Decide whether a schedule is due (now). */
export function isDue(s: Schedule, now = Date.now()): boolean {
  if (!s.enabled) return false;
  if (s.intervalMinutes) {
    return !s.lastRunAt || (now - s.lastRunAt) >= s.intervalMinutes * 60 * 1000;
  }
  if (s.dailyAt) {
    const [hh, mm] = s.dailyAt.split(":").map(Number);
    const today = new Date(now);
    const due = new Date(today.getFullYear(), today.getMonth(), today.getDate(), hh, mm).getTime();
    // Already past today's due time AND last run was before today's due time.
    return now >= due && (!s.lastRunAt || s.lastRunAt < due);
  }
  return false;
}

// ─────────────────────────── Tick loop ────────────────────────────────
let started = false;
declare global {
  // eslint-disable-next-line no-var
  var __mobaScheduleTimer: NodeJS.Timeout | undefined;
}

/** Idempotent — the API route calls this once. */
export function startScheduler() {
  if (started || globalThis.__mobaScheduleTimer) return;
  started = true;
  // Tick every minute.
  globalThis.__mobaScheduleTimer = setInterval(async () => {
    try {
      const items = await load();
      for (const s of items) {
        if (!isDue(s)) continue;
        await dispatchScan(s);
      }
    } catch (e) { console.warn("[scheduler]", e); }
  }, 60_000);
}

async function dispatchScan(s: Schedule) {
  // Resolve a same-process URL — works inside Next.js dev / prod.
  const port = process.env.PORT || 3000;
  // Try a few common dev/prod ports if PORT is unset.
  const candidates = [Number(port), 3000, 16136];
  for (const p of [...new Set(candidates)]) {
    try {
      const r = await fetch(`http://127.0.0.1:${p}/api/scans`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(s.scanRequest),
      });
      if (r.ok) {
        const { id } = await r.json();
        await updateSchedule(s.id, { lastRunAt: Date.now(), lastScanId: id });
        return;
      }
    } catch { /* try next port */ }
  }
}

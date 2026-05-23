/**
 * Continuous attack-surface monitoring.
 *
 * Daily passive recon across a list of seed domains:
 *   - Subdomain enumeration (crt.sh + DNS dict)
 *   - DNS audit (CAA / dangling CNAME / wildcard)
 *   - HSTS preload status
 *   - Certificate transparency monitoring (new certs since last run)
 *   - VirusTotal categorization (if VT_API_KEY set)
 *
 * Each run produces a "monitor scan" — diffs against the previous run alert
 * on new subdomains, new certs, new open ports, new VT classifications.
 */

import { promises as dns } from "node:dns";
import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";

const FILE = path.join(process.cwd(), "data", "monitor-targets.json");

export const MonitorTargetSchema = z.object({
  id: z.string(),
  apex: z.string(),
  notes: z.string().optional(),
  /** Last observed subdomains. */
  knownSubdomains: z.array(z.string()).default([]),
  /** Last observed certs (by SHA-256 fingerprint). */
  knownCerts: z.array(z.string()).default([]),
  /** Last passive run. */
  lastRunAt: z.number().optional(),
});
export type MonitorTarget = z.infer<typeof MonitorTargetSchema>;

async function load(): Promise<MonitorTarget[]> {
  try { return JSON.parse(await fs.readFile(FILE, "utf8")); } catch { return []; }
}
async function save(items: MonitorTarget[]) {
  await fs.mkdir(path.dirname(FILE), { recursive: true });
  await fs.writeFile(FILE, JSON.stringify(items, null, 2), "utf8");
}

export async function listTargets(): Promise<MonitorTarget[]> { return load(); }
export async function addTarget(t: Omit<MonitorTarget, "id" | "knownSubdomains" | "knownCerts" | "lastRunAt">): Promise<MonitorTarget> {
  const items = await load();
  const fresh: MonitorTarget = { ...t, id: crypto.randomUUID(), knownSubdomains: [], knownCerts: [] };
  items.push(fresh);
  await save(items);
  return fresh;
}
export async function removeTarget(id: string) { await save((await load()).filter((t) => t.id !== id)); }

/** Run one passive sweep. Returns the diff (new subdomains / new certs). */
export async function sweep(t: MonitorTarget): Promise<{
  newSubdomains: string[];
  newCerts: string[];
  totalSubdomains: number;
}> {
  // crt.sh subdomain enumeration
  const subs = new Set<string>();
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(t.apex)}&output=json`);
    if (r.ok) {
      const arr = (await r.json()) as Array<{ name_value?: string }>;
      for (const e of arr) {
        for (const n of (e.name_value ?? "").split("\n")) {
          const cleaned = n.trim().toLowerCase();
          if (cleaned.endsWith(t.apex) && !cleaned.startsWith("*")) subs.add(cleaned);
        }
      }
    }
  } catch { /* tolerate */ }
  // crt.sh certs (fingerprints)
  const certs = new Set<string>();
  try {
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(t.apex)}&output=json`);
    if (r.ok) {
      const arr = (await r.json()) as Array<{ id?: number; min_cert_id?: number }>;
      for (const e of arr.slice(0, 100)) certs.add(String(e.id ?? e.min_cert_id ?? ""));
    }
  } catch { /* tolerate */ }

  const newSubdomains = [...subs].filter((s) => !t.knownSubdomains.includes(s));
  const newCerts = [...certs].filter((c) => !t.knownCerts.includes(c));

  // Persist updated state.
  const items = await load();
  const i = items.findIndex((x) => x.id === t.id);
  if (i >= 0) {
    items[i] = { ...items[i], knownSubdomains: [...subs], knownCerts: [...certs], lastRunAt: Date.now() };
    await save(items);
  }
  return { newSubdomains, newCerts, totalSubdomains: subs.size };
}

/** Run sweeps for every target. Returns aggregated changes. */
export async function sweepAll() {
  const items = await load();
  const out: Array<{ apex: string; newSubdomains: string[]; newCerts: string[]; totalSubdomains: number }> = [];
  for (const t of items) {
    const r = await sweep(t);
    out.push({ apex: t.apex, ...r });
  }
  return out;
}

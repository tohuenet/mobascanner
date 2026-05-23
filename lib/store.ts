/**
 * Lightweight JSON-file persistence for scans + findings.
 *
 * Why JSON files instead of SQLite:
 * - Zero native deps → Windows-friendly, no node-gyp.
 * - Each scan gets its own folder so we can stream findings as JSONL without
 *   global locks. Aggregations are cheap because scans are short-lived units
 *   of work, not long-running ledgers.
 *
 * Layout:
 *   data/
 *     scans/
 *       <scanId>/
 *         scan.json        — Scan metadata (status, counts, progress)
 *         findings.jsonl   — One Finding per line, append-only
 *         logs.jsonl       — One log line per entry
 *     index.json           — Array of {id, kind, status, createdAt} for list view
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { EMPTY_COUNTS, type Finding, type Scan } from "./types";

const DATA_ROOT = path.join(process.cwd(), "data");
const SCANS_ROOT = path.join(DATA_ROOT, "scans");
const INDEX_PATH = path.join(DATA_ROOT, "index.json");

async function ensureRoot() {
  await fs.mkdir(SCANS_ROOT, { recursive: true });
  try { await fs.access(INDEX_PATH); }
  catch { await fs.writeFile(INDEX_PATH, "[]", "utf8"); }
}

function scanDir(id: string) { return path.join(SCANS_ROOT, id); }

export interface ScanIndexEntry {
  id: string;
  kind: Scan["kind"];
  status: Scan["status"];
  target: string;
  createdAt: number;
  finishedAt?: number;
  counts: Record<string, number>;
}

async function readIndex(): Promise<ScanIndexEntry[]> {
  await ensureRoot();
  try {
    const raw = await fs.readFile(INDEX_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

async function writeIndex(entries: ScanIndexEntry[]) {
  await ensureRoot();
  await fs.writeFile(INDEX_PATH, JSON.stringify(entries, null, 2), "utf8");
}

function toIndex(scan: Scan): ScanIndexEntry {
  return {
    id: scan.id,
    kind: scan.kind,
    status: scan.status,
    target: scan.target.value,
    createdAt: scan.createdAt,
    finishedAt: scan.finishedAt,
    counts: scan.counts,
  };
}

export async function createScan(scan: Scan): Promise<void> {
  await fs.mkdir(scanDir(scan.id), { recursive: true });
  await fs.writeFile(
    path.join(scanDir(scan.id), "scan.json"),
    JSON.stringify(scan, null, 2),
    "utf8",
  );
  await fs.writeFile(path.join(scanDir(scan.id), "findings.jsonl"), "", "utf8");
  await fs.writeFile(path.join(scanDir(scan.id), "logs.jsonl"), "", "utf8");
  const idx = await readIndex();
  idx.unshift(toIndex(scan));
  await writeIndex(idx);
}

export async function getScan(id: string): Promise<Scan | null> {
  try {
    const raw = await fs.readFile(path.join(scanDir(id), "scan.json"), "utf8");
    return JSON.parse(raw) as Scan;
  } catch {
    return null;
  }
}

export async function updateScan(scan: Scan): Promise<void> {
  await fs.writeFile(
    path.join(scanDir(scan.id), "scan.json"),
    JSON.stringify(scan, null, 2),
    "utf8",
  );
  // Refresh index entry
  const idx = await readIndex();
  const i = idx.findIndex((e) => e.id === scan.id);
  if (i >= 0) idx[i] = toIndex(scan);
  else idx.unshift(toIndex(scan));
  await writeIndex(idx);
}

export async function appendFinding(scanId: string, finding: Finding): Promise<void> {
  const line = JSON.stringify(finding) + "\n";
  await fs.appendFile(path.join(scanDir(scanId), "findings.jsonl"), line, "utf8");
}

export async function listFindings(scanId: string): Promise<Finding[]> {
  try {
    const raw = await fs.readFile(path.join(scanDir(scanId), "findings.jsonl"), "utf8");
    if (!raw.trim()) return [];
    return raw.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Finding);
  } catch {
    return [];
  }
}

export async function listScans(): Promise<ScanIndexEntry[]> {
  return readIndex();
}

export async function deleteScan(id: string): Promise<void> {
  await fs.rm(scanDir(id), { recursive: true, force: true });
  const idx = await readIndex();
  await writeIndex(idx.filter((e) => e.id !== id));
}

export async function appendLog(
  scanId: string,
  level: "info" | "warn" | "error",
  message: string,
): Promise<void> {
  const entry = { at: Date.now(), level, message };
  await fs.appendFile(
    path.join(scanDir(scanId), "logs.jsonl"),
    JSON.stringify(entry) + "\n",
    "utf8",
  );
}

export function freshCounts() {
  return { ...EMPTY_COUNTS };
}

export const DATA_PATHS = { DATA_ROOT, SCANS_ROOT, INDEX_PATH };

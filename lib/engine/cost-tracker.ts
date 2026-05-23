/**
 * Per-scanner cost tracker — counts every outbound HTTP request and every
 * Anthropic API token used, attributed to the scanner that triggered it.
 *
 * The runner sets `currentScannerId` before invoking each scanner; instrument
 * code (BrowsingSession, agentic loop, LLM triage) reads this and increments
 * the right bucket. After the scan finishes, /api/scans/[id]/cost returns
 * the breakdown — useful for tuning which scanners to disable on big targets.
 */

interface Bucket {
  httpRequests: number;
  bytesIn: number;
  bytesOut: number;
  llmInputTokens: number;
  llmOutputTokens: number;
  llmCacheRead: number;
  ms: number;
}

declare global {
  // eslint-disable-next-line no-var
  var __mobaCostBuckets: Map<string, Map<string, Bucket>> | undefined;
}
const buckets = (globalThis.__mobaCostBuckets ??= new Map<string, Map<string, Bucket>>());

let currentScanId: string | null = null;
let currentScannerId: string | null = null;

export function startScannerCost(scanId: string, scannerId: string) {
  currentScanId = scanId;
  currentScannerId = scannerId;
  if (!buckets.has(scanId)) buckets.set(scanId, new Map());
  const m = buckets.get(scanId)!;
  if (!m.has(scannerId)) m.set(scannerId, { httpRequests: 0, bytesIn: 0, bytesOut: 0, llmInputTokens: 0, llmOutputTokens: 0, llmCacheRead: 0, ms: 0 });
}

export function endScannerCost() {
  currentScanId = null;
  currentScannerId = null;
}

function bucket(): Bucket | null {
  if (!currentScanId || !currentScannerId) return null;
  return buckets.get(currentScanId)?.get(currentScannerId) ?? null;
}

export function recordHttp(bytesIn: number, bytesOut: number, ms: number) {
  const b = bucket(); if (!b) return;
  b.httpRequests += 1; b.bytesIn += bytesIn; b.bytesOut += bytesOut; b.ms += ms;
}

export function recordLlm(input: number, output: number, cacheRead: number) {
  const b = bucket(); if (!b) return;
  b.llmInputTokens += input; b.llmOutputTokens += output; b.llmCacheRead += cacheRead;
}

export function getCostReport(scanId: string) {
  const m = buckets.get(scanId); if (!m) return [];
  const out: { scannerId: string; httpRequests: number; bytesIn: number; bytesOut: number; llmInputTokens: number; llmOutputTokens: number; llmCacheRead: number; ms: number }[] = [];
  for (const [scannerId, b] of m) out.push({ scannerId, ...b });
  return out.sort((a, b) => (b.httpRequests + b.llmInputTokens / 100) - (a.httpRequests + a.llmInputTokens / 100));
}
